mod json_parse;

use json_parse::ConfigJwt;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;

use std::collections::HashMap;

// We need to make sure a HTTP root context is created and initialized when the filter is initialized.
// The _start() function initialises this root context
#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(UpstreamCallRoot {
            config_jwt: ConfigJwt::new(),
        })
    });
}

// Defining standard CORS headers
static CORS_HEADERS: [(&str, &str); 5] = [
    ("Powered-By", "proxy-wasm"),
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "*"),
    ("Access-Control-Allow-Headers", "*"),
    ("Access-Control-Max-Age", "3600"),
];

// This struct is what the JWT token sent by the user will deserialize to
#[derive(Deserialize, Debug)]
struct Jwt {
    headers: HashMap<String,String>,
    payload: HashMap<String,String>,
}

impl Jwt {
    fn new() -> Self {
        Jwt {
            headers: HashMap::new(),
            payload: HashMap::new(),
        }
    }

    fn add_header(&mut self, key: &String, value: &String) {
        self.headers.insert(key.clone(), value.clone());
    }

    fn del_header(&mut self, key: &String) {
        self.headers.remove(key);
    }

    fn add_payload(&mut self, key: &String, value: &String) {
        self.payload.insert(key.clone(), value.clone());
    }

    fn del_payload(&mut self, key: &String) {
        self.payload.remove(key);
    }

    fn payload_to_header(&mut self, key: &String, value: &String) {
        self.del_payload(key);
        self.add_header(key, value);
    }

    fn header_to_payload(&mut self, key: &String, value: &String) {
        self.del_header(key);
        self.add_payload(key, value);
    }

    // Wrapper function to run operations
    fn modify_jwt(&mut self, config: &ConfigJwt) {
        for (i,j ) in config.add_header.iter() {
            self.add_header(&i,&j);
        }

        for i in config.del_header.iter() {
            self.del_header(&i);
        }

        for (i,j ) in config.add_payload.iter() {
            self.add_payload(&i,&j);
        }

        for i in config.del_payload.iter() {
            self.del_payload(&i);
        }

        for i in config.payload_to_header.iter() {
            let (key,value) = (i.clone(),self.payload.get(i).unwrap().clone());
            self.payload_to_header(&key,&value);
        }
        
        for i in config.header_to_payload.iter() {
            let (key,value) = (i.clone(),self.headers.get(i).unwrap().clone());
            self.header_to_payload(&key.clone(), &value.clone());
        }
    }
}

// This is the instance of a call made. It sorta derives from the root context
#[derive(Debug)]
struct UpstreamCall {
    config_jwt: ConfigJwt,
}

impl UpstreamCall {
    // Takes in the HashMap created in the root context mapping path name to rule type
    fn new(jwt: &ConfigJwt) -> Self {
        Self {
            config_jwt: jwt.clone(),
        }
    }
}

impl Context for UpstreamCall {}

impl HttpContext for UpstreamCall {
    fn on_http_request_headers(&mut self, _num_headers: usize) -> Action {
        if let Some(method) = self.get_http_request_header(":method") {
            if method == "OPTIONS" {
                self.send_http_response(204, CORS_HEADERS.to_vec(), None);
                return Action::Pause;
            }
        }

        
        if let Some(jwt) = self.get_http_request_header("Authorization") {
            // Decoding JWT token
            let mut split_jwt: Vec<String> = jwt.splitn(3,".").map(|s| s.to_string()).collect();
            let (h, p) = (&split_jwt[0], &split_jwt[1]);
            let mut jwt = Jwt::new();
            jwt.headers = serde_json::from_slice(&base64::decode(h).unwrap()).unwrap();
            jwt.payload = serde_json::from_slice(&base64::decode(p).unwrap()).unwrap();

            proxy_wasm::hostcalls::log(LogLevel::Debug, format!("Jwt: {:?}",jwt).as_str())
                .ok();

            jwt.modify_jwt(&self.config_jwt);

            let b64_header = base64::encode(serde_json::to_string(&jwt.headers).unwrap());
            let b64_payload = base64::encode(serde_json::to_string(&jwt.payload).unwrap());

            split_jwt[0] = b64_header; 
            split_jwt[1] = b64_payload;
            let new_jwt = split_jwt.join(".");            
            
            self.set_http_request_header("Authorization", Some(new_jwt.as_str()));

            // Initialising headers to send back
            let mut headers = CORS_HEADERS.to_vec();

            // Checking if the appropriate plan exists
            if false {
                self.send_http_response(
                    429,
                    headers,
                    Some(b"Invalid plan name or duplicate plan names defined.\n"),
                );
                return Action::Pause;
            }

            //proxy_wasm::hostcalls::log(LogLevel::Debug, format!("Obj {:?}", &rl).as_str())
            //    .ok();
            
            headers.append(&mut vec![("x-rate-limit", "1"), ("x-app-user", "2")]);
            self.send_http_response(200, headers, Some(b"OK\n"));
            return Action::Continue;
        }

        self.send_http_response(401, CORS_HEADERS.to_vec(), Some(b"Unauthorized\n"));
        Action::Pause
    }
    /*
    fn on_http_response_headers(&mut self, _num_headers: usize) -> Action {
        self.set_http_response_header("x-app-serving", Some("rate-limit-filter"));
        proxy_wasm::hostcalls::log(LogLevel::Debug, format!("RESPONDING").as_str()).ok();
        Action::Continue
    }
    */
}

struct UpstreamCallRoot {
    config_jwt: ConfigJwt,
}

impl Context for UpstreamCallRoot {}
impl<'a> RootContext for UpstreamCallRoot {
    //TODO: Revisit this once the read only feature is released in Istio 1.10
    // Get Base64 encoded JSON from envoy config file when WASM VM starts
    fn on_vm_start(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_configuration() {
            // bytestring passed by VM -> String of base64 encoded JSON
            let config_str = String::from_utf8(config_bytes).unwrap();
            // String of base64 encoded JSON -> bytestring of decoded JSON
            let config_b64 = base64::decode(config_str).unwrap();
            // bytestring of decoded JSON -> String of decoded JSON
            let json_str = String::from_utf8(config_b64).unwrap();
            // Creating HashMap of pattern ("path name", "rule type") and saving into UpstreamCallRoot object
            self.config_jwt=serde_json::from_str(&json_str).unwrap();
        }
        true
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        // creating UpstreamCall object for each new call
        Some(Box::new(UpstreamCall::new(&self.config_jwt)))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}
