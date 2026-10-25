/// The stable identity by which Muxlet copies recognise and exclude one another
/// (see DESIGN.md). `#[used]` and the `black_box` read keep it in optimised,
/// stripped builds; the library only ever assembles it at run time.
#[used]
static DISPATCHER_IDENTITY: &[u8] =
    b"\0Muxlet:dispatcher:v1:6cf54fa2-4329-46cc-9558-dc1aac2735eb\0";

fn main() {
    std::hint::black_box(DISPATCHER_IDENTITY);
    let code = muxlet::run(std::env::args_os().skip(1)).unwrap_or_else(|error| {
        eprintln!("muxlet: {error:#}");
        1
    });
    std::process::exit(code)
}
