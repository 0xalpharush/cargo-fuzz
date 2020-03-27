<div align="center">

  <h1><code>cargo fuzz</code></h1>

  <p><b>A <code>cargo</code> subcommand for using <code>libFuzzer</code>! Easy to use! No need to recompile LLVM!</b></p>

  <img alt="GitHub Actions Status" src="https://github.com/rust-fuzz/cargo-fuzz/workflows/ci/badge.svg"/>

</div>

## Installation

```sh
$ cargo install cargo-fuzz
```

Note: `libFuzzer` needs LLVM sanitizer support, so this only works on x86-64
Linux and x86-64 macOS for now. This also needs a nightly Rust toolchain since
it uses some unstable command-line flags. Finally, you'll also need a C++
compiler with C++11 support.

If you have an old version of `cargo fuzz`, you can upgrade with this command:

```sh
$ cargo install -f cargo-fuzz
```

## Usage

### `cargo fuzz init`

Initialize a `cargo fuzz` project for your crate!

### `cargo fuzz add <target>`

Create a new fuzzing target!

### `cargo fuzz run <target>`

Run a fuzzing target and find bugs!

### `cargo fuzz fmt <target> <input>`

Print debug output for an input test case!

### `cargo fuzz tmin <target> <input>`

Found a failing input? Minify it to the smallest input that causes that failure
for easier debugging!

### `cargo fuzz cmin <target>`

Minify your corpus of input files!

## Documentation

Documentation can be found in the [Rust Fuzz
Book](https://rust-fuzz.github.io/book/cargo-fuzz.html).

You can also always find the full command-line options that are available with
`--help`:

```sh
$ cargo fuzz --help
```

## Trophy case

[The trophy case](https://github.com/rust-fuzz/trophy-case) has a list of bugs
found by `cargo fuzz` (and others). Did `cargo fuzz` and libFuzzer find a bug
for you? Add it to the trophy case!

## License

`cargo-fuzz` is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-MIT](./LICENSE-MIT) for
details.
