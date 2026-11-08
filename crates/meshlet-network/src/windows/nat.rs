impl WindowsNetworkBackend {
    pub(super) fn meshlet_nat_owners_sync(&self) -> Result<Vec<String>, NetworkError> {
        Ok(Vec::new())
    }

    pub fn remove_nat_sync(&self, _owner: &str) -> Result<ApplyResult, NetworkError> {
        Err(NetworkError::Unsupported(
            "NAT rule removal on Windows is not yet implemented".to_string(),
        ))
    }
}
