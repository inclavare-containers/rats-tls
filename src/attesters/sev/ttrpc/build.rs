use ttrpc_codegen::Codegen;

fn main() {
    let protos = vec!["src/protocols/proto/aeb.proto"];

    Codegen::new()
        .out_dir("src/protocols/sev")
        .inputs(&protos)
        .include("src/protocols/proto")
        .rust_protobuf()
        .run()
        .expect("Generate code failed.");
}
