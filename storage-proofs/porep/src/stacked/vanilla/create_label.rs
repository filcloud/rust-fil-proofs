use std::collections::{BTreeMap, HashMap, HashSet};
use std::iter::FromIterator;
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use log::{info};
use sha2raw::Sha256;
use storage_proofs_core::{
    error::Result,
    hasher::Hasher,
    util::{data_at_node_offset, NODE_SIZE},
    drgraph::Graph,
};

use super::graph::StackedBucketGraph;

pub fn create_label<H: Hasher>(
    graph: &StackedBucketGraph<H>,
    replica_id: &H::Domain,
    layer_labels: &mut [u8],
    node: usize,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32];

    buffer[..8].copy_from_slice(&(node as u64).to_be_bytes());
    hasher.input(&[AsRef::<[u8]>::as_ref(replica_id), &buffer[..]][..]);

    // hash parents for all non 0 nodes
    let hash = if node > 0 {
        // prefetch previous node, which is always a parent
        let prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
        unsafe {
            _mm_prefetch(prev.as_ptr() as *const i8, _MM_HINT_T0);
        }

        graph.copy_parents_data(node as u32, &*layer_labels, hasher)
    } else {
        hasher.finish()
    };

    // store the newly generated key
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;
    layer_labels[start..end].copy_from_slice(&hash[..]);

    // strip last two bits, to ensure result is in Fr.
    layer_labels[end - 1] &= 0b0011_1111;

    Ok(())
}

pub fn create_label_exp<H: Hasher>(
    graph: &StackedBucketGraph<H>,
    replica_id: &H::Domain,
    exp_parents_data: &[u8],
    layer_labels: &mut [u8],
    node: usize,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32];

    buffer[..8].copy_from_slice(&(node as u64).to_be_bytes());
    hasher.input(&[AsRef::<[u8]>::as_ref(replica_id), &buffer[..]][..]);

    // hash parents for all non 0 nodes
    let hash = if node > 0 {
        // prefetch previous node, which is always a parent
        let prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
        unsafe {
            _mm_prefetch(prev.as_ptr() as *const i8, _MM_HINT_T0);
        }

        graph.copy_parents_data_exp(node as u32, &*layer_labels, exp_parents_data, hasher)
    } else {
        hasher.finish()
    };

    // store the newly generated key
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;
    layer_labels[start..end].copy_from_slice(&hash[..]);

    // strip last two bits, to ensure result is in Fr.
    layer_labels[end - 1] &= 0b0011_1111;

    Ok(())
}

pub fn prefetch_nodes<H: Hasher>(
    graph: &StackedBucketGraph<H>,
    layer_labels: &[u8],
    exp_parents_data: &[u8],
    node: usize,
    num: usize,
) -> Result<()> {
    let mut unlock_pages = HashMap::new();
    let mut locked_pages = HashMap::new();
    let mut lock_pages = HashMap::new();

    // Unlock last part
    let start = std::cmp::max(0, node as i64 - num as i64) as usize;
    let end = node;
    compute_pages(graph, layer_labels, exp_parents_data, start, end, &mut unlock_pages);

    // Locked next part
    let start = node;
    let end = std::cmp::min(graph.size(), start + num);
    compute_pages(graph, layer_labels, exp_parents_data, start, end, &mut locked_pages);

    // Lock next next part
    let start = std::cmp::min(graph.size(), node + num);
    let end = std::cmp::min(graph.size(), start + num);
    compute_pages(graph, layer_labels, exp_parents_data, start, end, &mut lock_pages);

    for addr in locked_pages.keys() {
        unlock_pages.remove(addr);
    }
    for addr in lock_pages.keys() {
        unlock_pages.remove(addr);
    }

    if node == 0 {
        // Lock first part
        for (addr, size) in locked_pages {
            lock_pages.insert(addr, size);
        }
    }

    info!("munlock {} pages for {} nodes: begin", unlock_pages.len(), num);
    let unlock_pages = BTreeMap::from_iter(unlock_pages);
    munlock(&unlock_pages)?;
    info!("munlock {} pages for {} nodes: end", unlock_pages.len(), num);

    info!("mlock {} pages for {} nodes: begin", lock_pages.len(), num);
    let lock_pages = BTreeMap::from_iter(lock_pages);
    mlock(&lock_pages)?;
    let mut total_nodes = 0usize;
    for (&addr, size) in lock_pages.iter() {
        println!("lock_pages: page {:p}, nodes {}", addr as *const u8, (*size).1.len());
        total_nodes += (*size).1.len();
    }
    info!("mlock {} pages for {} nodes but actually {} nodes: end", lock_pages.len(), total_nodes, num);

    Ok(())
}

fn compute_pages<H: Hasher>(
    graph: &StackedBucketGraph<H>,
    layer_labels: &[u8],
    exp_parents_data: &[u8],
    start_node: usize,
    end_node: usize,
    pages: &mut HashMap<usize, (usize, HashSet<usize>)>,
) {
    info!("compute_pages: {} - {}", start_node, end_node);
    for node in start_node..end_node {
        if let Some(cache) = graph.cache {
            let cache_parents = cache.read(node as u32);
            compute_pages_inner(layer_labels, exp_parents_data, cache_parents, node, pages);
        } else {
            let mut cache_parents = [0u32; super::graph::DEGREE];
            graph.parents(node as usize, &mut cache_parents[..]).unwrap();
            compute_pages_inner(layer_labels, exp_parents_data, &cache_parents, node, pages);
        }
    }
}

fn compute_pages_inner(
    layer_labels: &[u8],
    exp_parents_data: &[u8],
    parents: &[u32],
    node: usize,
    pages: &mut HashMap<usize, (usize, HashSet<usize>)>,
) {
    build_pages(&[node as u32], layer_labels, pages);

    build_pages(&parents[..storage_proofs_core::drgraph::BASE_DEGREE], layer_labels, pages);

    if !exp_parents_data.is_empty() {
        build_pages(&parents[storage_proofs_core::drgraph::BASE_DEGREE..], exp_parents_data, pages);
    }
}

#[inline]
fn build_pages(nodes: &[u32], data: &[u8], pages: &mut HashMap<usize, (usize, HashSet<usize>)>) {
    for node in nodes {
        let start = *node as usize * NODE_SIZE;
        let end = start + NODE_SIZE;
        let data = &data[start..end];

        let addr = region::page::floor(data.as_ptr() as usize);
        let size = region::page::size_from_range(data.as_ptr(), data.len());
        match pages.get_mut(&addr) {
            Some(second) => {
                let (ref mut ssize, ref mut count) = *second;
                (*count).insert(start);
                if *ssize < size {
                    *ssize = size;
                }
            }
            None => {
                pages.insert(addr, (size, HashSet::new()));
            },
        }
    }
}

#[inline]
fn mlock(pages: &BTreeMap<usize, (usize, HashSet<usize>)>) -> Result<()> {
    for (&addr, size) in pages {
        unsafe {
            region::lock(addr as *const u8, (*size).0)?.release();
        }
    }
    Ok(())
}

#[inline]
fn munlock(pages: &BTreeMap<usize, (usize, HashSet<usize>)>) -> Result<()> {
    for (&addr, size) in pages {
        unsafe {
            region::unlock(addr as *const u8, (*size).0)?;
        }
    }
    Ok(())
}
