use std::io::Result;

fn main() -> Result<()> {
    prost_build::Config::new()
        .out_dir("src/")
        .type_attribute(".", "#[derive(::serde::Serialize, ::serde::Deserialize)]")
        .type_attribute(".", "#[serde(rename_all = \"camelCase\")]")
        .compile_protos(
            &[
                "../proto/verdant/common.proto",
                "../proto/verdant/models.proto",
                "../proto/verdant/cache.proto",
                "../proto/verdant/ws.proto",
                "../proto/verdant/verdantdb_query.proto",
                "../proto/verdant/cross_region_event.proto",
            ],
            &["../proto"],
        )?;
    Ok(())
}
