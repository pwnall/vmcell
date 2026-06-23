use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Hello,
    Ready,
    Exec(ExecRequest),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
    PutFile { dst: String, bytes: Vec<u8> },
    Ping,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
}

#[derive(Debug)]
pub struct ExecOutcome {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialization() {
        let msg = Message::Exec(ExecRequest {
            argv: vec!["ls".to_string(), "-l".to_string()],
            env: vec![("PATH".to_string(), "/bin".to_string())],
            cwd: Some("/root".to_string()),
        });

        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        
        match decoded {
            Message::Exec(req) => {
                assert_eq!(req.argv, vec!["ls", "-l"]);
                assert_eq!(req.cwd, Some("/root".to_string()));
            }
            _ => panic!("wrong type"),
        }
    }
}
