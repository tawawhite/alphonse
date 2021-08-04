use anyhow::Result;
use elasticsearch::http::response::Response;
use serde_json::json;

/// Handle Elasticsearch general response
pub async fn handle_resp(resp: Response) -> Result<()> {
    let code = resp.status_code();
    match code.as_u16() {
        code if code >= 200 && code < 300 => {}
        c => {
            eprintln!("status code: {}", c);
            eprintln!("response message: {}", resp.text().await?);
        }
    };
    Ok(())
}

/// Handle Elasticsearch Bulk Index operation response
pub async fn handle_bulk_index_resp(resp: Response) -> Result<()> {
    let code = resp.status_code();
    match code.as_u16() {
        code if code >= 200 && code < 300 => {
            let j: serde_json::Value = resp.json().await?;
            let errors = j
                .get("errors")
                .unwrap_or(&json!(false))
                .as_bool()
                .unwrap_or_default();
            if errors {
                eprintln!("Elasticsearch bulk request succeed, but some index operation failed");
                let tmp1 = json!([]);
                let tmp2 = vec![];
                let items = j.get("items").unwrap_or(&tmp1).as_array().unwrap_or(&tmp2);
                for item in items {
                    let obj = json!({});
                    let map = serde_json::Map::default();
                    let index = item
                        .get("index")
                        .unwrap_or(&obj)
                        .as_object()
                        .unwrap_or(&map);
                    eprintln!(
                        "error: {}",
                        serde_json::to_string(&index).unwrap_or_default()
                    );
                }
            }
        }
        c => {
            eprintln!("status code: {}", c);
            eprintln!("response message: {}", resp.text().await?);
        }
    };
    Ok(())
}
