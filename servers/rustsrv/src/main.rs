use std::{io::BufReader, net::TcpListener, sync::Arc, thread};
use rustls::crypto::aws_lc_rs as p;

fn main() {
    let addr = std::env::args().nth(1).unwrap_or("127.0.0.1:9447".into());
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open("../cert.pem").unwrap()))
        .collect::<Result<Vec<_>, _>>().unwrap();
    let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open("../key.pem").unwrap()))
        .unwrap().unwrap();
    let mut prov = p::default_provider();
    prov.kx_groups = p::ALL_KX_GROUPS.to_vec();
    eprintln!("kx groups: {:?}", prov.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>());
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(prov))
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_no_client_auth().with_single_cert(certs, key).unwrap());
    for s in TcpListener::bind(addr).unwrap().incoming().flatten() {
        let cfg = cfg.clone();
        thread::spawn(move || {
            let mut s = s;
            let mut c = rustls::ServerConnection::new(cfg).unwrap();
            if let Err(e) = c.complete_io(&mut s) { eprintln!("hs: {e}"); }
            let _ = c.complete_io(&mut s);
        });
    }
}
