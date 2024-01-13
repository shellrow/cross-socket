use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserInfo {
    pub id: String,
    pub group_id: String,
    pub name: String,
    pub groups: Vec<String>,
}
