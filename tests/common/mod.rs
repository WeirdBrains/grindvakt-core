//! An in-memory DNS zone that records every write.
#![allow(dead_code)]
use grindvakt_core::Result;
use grindvakt_core::provider::DnsProvider;
use grindvakt_core::record::{ExistingRecord, RecordKind, RecordValue};
use std::sync::Mutex;

#[derive(Default)]
pub struct Memory {
    pub records: Mutex<Vec<ExistingRecord>>,
    pub writes: Mutex<Vec<String>>,
}

impl Memory {
    pub fn with(records: Vec<ExistingRecord>) -> Self {
        Self {
            records: Mutex::new(records),
            writes: Mutex::default(),
        }
    }
    pub fn writes(&self) -> Vec<String> {
        self.writes.lock().unwrap().clone()
    }
}

pub fn existing(id: u64, name: &str, value: RecordValue, ttl: u32) -> ExistingRecord {
    ExistingRecord {
        id,
        name: name.into(),
        value,
        ttl: Some(ttl),
    }
}

impl DnsProvider for Memory {
    fn name(&self) -> &str {
        "memory"
    }
    async fn list(&self, _zone: &str, name: &str, kind: RecordKind) -> Result<Vec<ExistingRecord>> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.name == name && r.value.kind() == kind)
            .cloned()
            .collect())
    }
    async fn create(&self, _zone: &str, name: &str, value: &RecordValue, ttl: u32) -> Result<()> {
        self.writes
            .lock()
            .unwrap()
            .push(format!("create {name:?} {value} {ttl}"));
        let mut r = self.records.lock().unwrap();
        let id = r.iter().map(|x| x.id).max().unwrap_or(0) + 1;
        r.push(existing(id, name, value.clone(), ttl));
        Ok(())
    }
    async fn update(&self, _zone: &str, id: u64, value: &RecordValue, ttl: u32) -> Result<()> {
        self.writes
            .lock()
            .unwrap()
            .push(format!("update {id} {value} {ttl}"));
        for r in self
            .records
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|r| r.id == id)
        {
            r.value = value.clone();
            r.ttl = Some(ttl);
        }
        Ok(())
    }
}
