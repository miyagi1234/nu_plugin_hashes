use nu_cmd_base::input_handler::{operate, CmdArgument};
use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand};
use nu_protocol::{
    ast::CellPath, Category, Example, IntoPipelineData, LabeledError, PipelineData, ShellError,
    Signature, Span, SyntaxShape, Type, Value,
};
use std::ops::Not;

use crate::HashesPlugin;

// ==========================================
// --- BLAKE2B VARIABLE SIZE ---
// ==========================================

#[cfg(feature = "blake2")]
pub struct Blake2bVarCommand;

#[cfg(feature = "blake2")]
struct Blake2bVarArguments {
    cell_paths: Option<Vec<CellPath>>,
    binary: bool,
    size: usize,
}

#[cfg(feature = "blake2")]
impl CmdArgument for Blake2bVarArguments {
    fn take_cell_paths(&mut self) -> Option<Vec<CellPath>> { self.cell_paths.take() }
}

#[cfg(feature = "blake2")]
impl PluginCommand for Blake2bVarCommand {
    type Plugin = HashesPlugin;

    fn name(&self) -> &str { "hash blake2b" }

    fn signature(&self) -> Signature {
        Signature::build(self.name())
            .category(Category::Hash)
            .input_output_types(vec![
                (Type::Binary, Type::Any), (Type::String, Type::Any),
                (Type::table(), Type::table()), (Type::record(), Type::record()),
            ])
            .named("size", SyntaxShape::Int, "Output size in bytes (1 to 64). Default is 64", Some('s'))
            .switch("binary", "Output binary instead of hexadecimal representation", Some('b'))
            .rest("rest", SyntaxShape::CellPath, "Optionally hash data by cell path")
    }

    fn description(&self) -> &str {
        "Hash a value using the blake2b hash algorithm with variable runtime-defined output size."
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example { description: "Return the blake2b hash of a string, hex-encoded (default 64 bytes)", example: "'hello world' | hash blake2b", result: None },
            Example { description: "Return the blake2b hash with 32 bytes output", example: "'hello world' | hash blake2b --size 32", result: None },
        ]
    }

    fn run(&self, _plugin: &HashesPlugin, engine: &EngineInterface, call: &EvaluatedCall, input: PipelineData) -> Result<PipelineData, LabeledError> {
        let head = call.head;
        let binary = call.has_flag("binary")?;
        let size_opt: Option<i64> = call.get_flag("size")?;

        let size = match size_opt {
            Some(s) if s > 0 && s <= 64 => s as usize,
            Some(_) => return Err(LabeledError::new("Size must be between 1 and 64 bytes").with_label("Invalid size", head)),
            None => 64,
        };

        let cell_paths: Vec<CellPath> = call.rest(0)?;
        let cell_paths = cell_paths.is_empty().not().then_some(cell_paths);

        if let PipelineData::ByteStream(stream, ..) = input {
            use blake2::Blake2bVar;
            let mut hasher = Blake2bVar::new(size).map_err(|e| LabeledError::new(e.to_string()))?;

            struct WriteBlake<'a>(&'a mut Blake2bVar);
            impl<'a> std::io::Write for WriteBlake<'a> {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    use blake2::digest::Update;
                    self.0.update(buf);
                    Ok(buf.len())
                }
                fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
            }

            stream.write_to(&mut WriteBlake(&mut hasher))?;

            use blake2::digest::VariableOutput;
            let mut buf = vec![0u8; size];
            hasher.finalize_variable(&mut buf).map_err(|e| LabeledError::new(e.to_string()))?;

            if binary { Ok(Value::binary(buf, head).into_pipeline_data()) }
            else { Ok(Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), head).into_pipeline_data()) }
        } else {
            operate(blake2b_action, Blake2bVarArguments { binary, cell_paths, size }, input, head, engine.signals()).map_err(Into::into)
        }
    }
}

#[cfg(feature = "blake2")]
fn blake2b_action(input: &Value, args: &Blake2bVarArguments, span: Span) -> Value {
    let (bytes, span) = match input {
        Value::String { val, .. } => (val.as_bytes(), span),
        Value::Binary { val, .. } => (val.as_slice(), span),
        Value::Error { .. } => return input.clone(),
        other => return Value::error(ShellError::OnlySupportsThisInputType { exp_input_type: "string or binary".into(), wrong_type: other.get_type().to_string(), dst_span: span, src_span: other.span() }, span),
    };

    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;
    let mut hasher = Blake2bVar::new(args.size).unwrap();
    hasher.update(bytes);
    let mut buf = vec![0u8; args.size];
    hasher.finalize_variable(&mut buf).unwrap();

    if args.binary { Value::binary(buf, span) }
    else { Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), span) }
}

// ==========================================
// --- SHA-1 WITH COLLISION DETECTION ---
// ==========================================

#[cfg(feature = "sha1-checked")]
pub struct Sha1CheckedCommand;

#[cfg(feature = "sha1-checked")]
struct Sha1CheckedArguments {
    cell_paths: Option<Vec<CellPath>>,
    binary: bool,
}

#[cfg(feature = "sha1-checked")]
impl CmdArgument for Sha1CheckedArguments {
    fn take_cell_paths(&mut self) -> Option<Vec<CellPath>> { self.cell_paths.take() }
}

#[cfg(feature = "sha1-checked")]
impl PluginCommand for Sha1CheckedCommand {
    type Plugin = HashesPlugin;

    fn name(&self) -> &str { "hash sha1-checked" }

    fn signature(&self) -> Signature {
        Signature::build(self.name())
            .category(Category::Hash)
            .input_output_types(vec![
                (Type::Binary, Type::Any), (Type::String, Type::Any),
                (Type::table(), Type::table()), (Type::record(), Type::record()),
            ])
            .switch("binary", "Output binary instead of hexadecimal representation", Some('b'))
            .rest("rest", SyntaxShape::CellPath, "Optionally hash data by cell path")
    }

    fn description(&self) -> &str {
        "Hash a value using SHA-1, failing safely if a collision attack is detected."
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![ Example { description: "Return the checked SHA-1 hash of a string", example: "'hello world' | hash sha1-checked", result: None } ]
    }

    fn run(&self, _plugin: &HashesPlugin, engine: &EngineInterface, call: &EvaluatedCall, input: PipelineData) -> Result<PipelineData, LabeledError> {
        let head = call.head;
        let binary = call.has_flag("binary")?;
        let cell_paths: Vec<CellPath> = call.rest(0)?;
        let cell_paths = cell_paths.is_empty().not().then_some(cell_paths);

        if let PipelineData::ByteStream(stream, ..) = input {
            use sha1_checked::Sha1;
            let mut hasher = Sha1::new();

            struct WriteSha1<'a>(&'a mut Sha1);
            impl<'a> std::io::Write for WriteSha1<'a> {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    use sha1_checked::Digest;
                    self.0.update(buf);
                    Ok(buf.len())
                }
                fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
            }

            stream.write_to(&mut WriteSha1(&mut hasher))?;

            let res = hasher.try_finalize();
            if res.has_collision() {
                return Err(LabeledError::new("SHA-1 collision detected!").with_label("Collision vulnerability found in stream", head));
            }
            let digest = res.hash();

            if binary { Ok(Value::binary(digest.to_vec(), head).into_pipeline_data()) }
            else { Ok(Value::string(digest.iter().map(|b| format!("{:02x}", b)).collect::<String>(), head).into_pipeline_data()) }
        } else {
            operate(sha1_checked_action, Sha1CheckedArguments { binary, cell_paths }, input, head, engine.signals()).map_err(Into::into)
        }
    }
}

#[cfg(feature = "sha1-checked")]
fn sha1_checked_action(input: &Value, args: &Sha1CheckedArguments, span: Span) -> Value {
    let (bytes, span) = match input {
        Value::String { val, .. } => (val.as_bytes(), span),
        Value::Binary { val, .. } => (val.as_slice(), span),
        Value::Error { .. } => return input.clone(),
        other => return Value::error(ShellError::OnlySupportsThisInputType { exp_input_type: "string or binary".into(), wrong_type: other.get_type().to_string(), dst_span: span, src_span: other.span() }, span),
    };

    use sha1_checked::{Sha1, Digest};
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    let res = hasher.try_finalize();

    if res.has_collision() {
        return Value::error(LabeledError::new("SHA-1 collision detected!").with_label("Collision vulnerability found in input", span).into(), span);
    }

    let digest = res.hash();
    if args.binary { Value::binary(digest.to_vec(), span) }
    else { Value::string(digest.iter().map(|b| format!("{:02x}", b)).collect::<String>(), span) }
}

// ==========================================
// --- DIRECT XOF MACRO (For cSHAKE) ---
// ==========================================

macro_rules! implement_tk_cshake {
    ($cmd_name:literal, $struct_name:ident, $arg_struct_name:ident, $fn_name:ident, $desc:literal, $example:literal, $init:expr) => {
        pub struct $struct_name;

        struct $arg_struct_name {
            cell_paths: Option<Vec<CellPath>>,
            binary: bool,
            size: usize,
        }

        impl CmdArgument for $arg_struct_name {
            fn take_cell_paths(&mut self) -> Option<Vec<CellPath>> { self.cell_paths.take() }
        }

        impl PluginCommand for $struct_name {
            type Plugin = HashesPlugin;
            fn name(&self) -> &str { $cmd_name }
            fn description(&self) -> &str { $desc }

            fn signature(&self) -> Signature {
                Signature::build(self.name())
                    .category(Category::Hash)
                    .input_output_types(vec![ (Type::Binary, Type::Any), (Type::String, Type::Any), (Type::table(), Type::table()), (Type::record(), Type::record()) ])
                    .named("size", SyntaxShape::Int, "Output size in bytes. Default is 32", Some('s'))
                    .switch("binary", "Output binary instead of hexadecimal representation", Some('b'))
                    .rest("rest", SyntaxShape::CellPath, "Optionally hash data by cell path")
            }

            fn examples(&self) -> Vec<Example<'_>> {
                vec![ Example { description: "Hash a value with the default 32-byte output", example: $example, result: None } ]
            }

            fn run(&self, _p: &HashesPlugin, engine: &EngineInterface, call: &EvaluatedCall, input: PipelineData) -> Result<PipelineData, LabeledError> {
                let head = call.head;
                let binary = call.has_flag("binary")?;
                let size = match call.get_flag::<i64>("size")? {
                    Some(s) if s > 0 => s as usize,
                    Some(_) => return Err(LabeledError::new("Size must be greater than 0").with_label("Invalid size", head)),
                    None => 32,
                };
                let cell_paths: Vec<CellPath> = call.rest(0)?;
                let cell_paths = cell_paths.is_empty().not().then_some(cell_paths);

                if let PipelineData::ByteStream(stream, ..) = input {
                    use tiny_keccak::{Hasher, Xof};
                    let mut hasher = $init;

                    struct WriteTK<'a, T>(&'a mut T);
                    impl<'a, T: Hasher> std::io::Write for WriteTK<'a, T> {
                        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                            self.0.update(buf);
                            Ok(buf.len())
                        }
                        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
                    }

                    stream.write_to(&mut WriteTK(&mut hasher))?;

                    let mut buf = vec![0u8; size];
                    hasher.squeeze(&mut buf); // NO INTO_XOF() NEEDED HERE

                    if binary { Ok(Value::binary(buf, head).into_pipeline_data()) }
                    else { Ok(Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), head).into_pipeline_data()) }
                } else {
                    operate($fn_name, $arg_struct_name { binary, cell_paths, size }, input, head, engine.signals()).map_err(Into::into)
                }
            }
        }

        fn $fn_name(input: &Value, args: &$arg_struct_name, span: Span) -> Value {
            let (bytes, span) = match input {
                Value::String { val, .. } => (val.as_bytes(), span),
                Value::Binary { val, .. } => (val.as_slice(), span),
                Value::Error { .. } => return input.clone(),
                other => return Value::error(ShellError::OnlySupportsThisInputType { exp_input_type: "string or binary".into(), wrong_type: other.get_type().to_string(), dst_span: span, src_span: other.span() }, span),
            };

            use tiny_keccak::{Hasher, Xof};
            let mut hasher = $init;
            hasher.update(bytes);
            let mut buf = vec![0u8; args.size];
            hasher.squeeze(&mut buf); // NO INTO_XOF() NEEDED HERE

            if args.binary { Value::binary(buf, span) }
            else { Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), span) }
        }
    };
}

#[cfg(feature = "cshake")]
implement_tk_cshake!("hash cshake128", CShake128Command, CShake128Args, cshake128_action, "Hash a value using the cSHAKE128 XOF.", "'hello world' | hash cshake128", tiny_keccak::CShake::v128(b"", b""));

#[cfg(feature = "cshake")]
implement_tk_cshake!("hash cshake256", CShake256Command, CShake256Args, cshake256_action, "Hash a value using the cSHAKE256 XOF.", "'hello world' | hash cshake256", tiny_keccak::CShake::v256(b"", b""));


// ==========================================
// --- TRANSITION XOF MACRO (Tuple/K12) ---
// ==========================================

macro_rules! implement_tk_transition_xof {
    ($cmd_name:literal, $struct_name:ident, $arg_struct_name:ident, $fn_name:ident, $desc:literal, $example:literal, $init:expr) => {
        pub struct $struct_name;

        struct $arg_struct_name {
            cell_paths: Option<Vec<CellPath>>,
            binary: bool,
            size: usize,
        }

        impl CmdArgument for $arg_struct_name {
            fn take_cell_paths(&mut self) -> Option<Vec<CellPath>> { self.cell_paths.take() }
        }

        impl PluginCommand for $struct_name {
            type Plugin = HashesPlugin;
            fn name(&self) -> &str { $cmd_name }
            fn description(&self) -> &str { $desc }

            fn signature(&self) -> Signature {
                Signature::build(self.name())
                    .category(Category::Hash)
                    .input_output_types(vec![ (Type::Binary, Type::Any), (Type::String, Type::Any), (Type::table(), Type::table()), (Type::record(), Type::record()) ])
                    .named("size", SyntaxShape::Int, "Output size in bytes. Default is 32", Some('s'))
                    .switch("binary", "Output binary instead of hexadecimal representation", Some('b'))
                    .rest("rest", SyntaxShape::CellPath, "Optionally hash data by cell path")
            }

            fn examples(&self) -> Vec<Example<'_>> {
                vec![ Example { description: "Hash a value with the default 32-byte output", example: $example, result: None } ]
            }

            fn run(&self, _p: &HashesPlugin, engine: &EngineInterface, call: &EvaluatedCall, input: PipelineData) -> Result<PipelineData, LabeledError> {
                let head = call.head;
                let binary = call.has_flag("binary")?;
                let size = match call.get_flag::<i64>("size")? {
                    Some(s) if s > 0 => s as usize,
                    Some(_) => return Err(LabeledError::new("Size must be greater than 0").with_label("Invalid size", head)),
                    None => 32,
                };
                let cell_paths: Vec<CellPath> = call.rest(0)?;
                let cell_paths = cell_paths.is_empty().not().then_some(cell_paths);

                if let PipelineData::ByteStream(stream, ..) = input {
                    use tiny_keccak::{Hasher, IntoXof, Xof};
                    let mut hasher = $init;

                    struct WriteTK<'a, T>(&'a mut T);
                    impl<'a, T: Hasher> std::io::Write for WriteTK<'a, T> {
                        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                            self.0.update(buf);
                            Ok(buf.len())
                        }
                        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
                    }

                    stream.write_to(&mut WriteTK(&mut hasher))?;

                    let mut xof = hasher.into_xof(); // LOCKS THE STATE
                    let mut buf = vec![0u8; size];
                    xof.squeeze(&mut buf);

                    if binary { Ok(Value::binary(buf, head).into_pipeline_data()) }
                    else { Ok(Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), head).into_pipeline_data()) }
                } else {
                    operate($fn_name, $arg_struct_name { binary, cell_paths, size }, input, head, engine.signals()).map_err(Into::into)
                }
            }
        }

        fn $fn_name(input: &Value, args: &$arg_struct_name, span: Span) -> Value {
            let (bytes, span) = match input {
                Value::String { val, .. } => (val.as_bytes(), span),
                Value::Binary { val, .. } => (val.as_slice(), span),
                Value::Error { .. } => return input.clone(),
                other => return Value::error(ShellError::OnlySupportsThisInputType { exp_input_type: "string or binary".into(), wrong_type: other.get_type().to_string(), dst_span: span, src_span: other.span() }, span),
            };

            use tiny_keccak::{Hasher, IntoXof, Xof};
            let mut hasher = $init;
            hasher.update(bytes);
            let mut xof = hasher.into_xof(); // LOCKS THE STATE
            let mut buf = vec![0u8; args.size];
            xof.squeeze(&mut buf);

            if args.binary { Value::binary(buf, span) }
            else { Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), span) }
        }
    };
}

#[cfg(feature = "k12")]
implement_tk_transition_xof!("hash kangaroo-twelve", KangarooTwelveCommand, K12Args, k12_action, "Hash a value using the KangarooTwelve XOF.", "'hello world' | hash kangaroo-twelve", tiny_keccak::KangarooTwelve::new(b""));

#[cfg(feature = "tuple_hash")]
implement_tk_transition_xof!("hash tuple-hash128", TupleHash128Command, TupleHash128Args, tuple128_action, "Hash a value using the TupleHash128 XOF.", "'hello world' | hash tuple-hash128", tiny_keccak::TupleHash::v128(b""));

#[cfg(feature = "tuple_hash")]
implement_tk_transition_xof!("hash tuple-hash256", TupleHash256Command, TupleHash256Args, tuple256_action, "Hash a value using the TupleHash256 XOF.", "'hello world' | hash tuple-hash256", tiny_keccak::TupleHash::v256(b""));


// ==========================================
// --- KMAC ALGORITHMS ---
// ==========================================

macro_rules! implement_tk_kmac {
    ($cmd_name:literal, $struct_name:ident, $arg_struct_name:ident, $fn_name:ident, $desc:literal, $example:literal, $init_path:path) => {
        pub struct $struct_name;

        struct $arg_struct_name {
            cell_paths: Option<Vec<CellPath>>,
            binary: bool,
            size: usize,
            key: String,
        }

        impl CmdArgument for $arg_struct_name {
            fn take_cell_paths(&mut self) -> Option<Vec<CellPath>> { self.cell_paths.take() }
        }

        impl PluginCommand for $struct_name {
            type Plugin = HashesPlugin;
            fn name(&self) -> &str { $cmd_name }
            fn description(&self) -> &str { $desc }

            fn signature(&self) -> Signature {
                Signature::build(self.name())
                    .category(Category::Hash)
                    .input_output_types(vec![ (Type::Binary, Type::Any), (Type::String, Type::Any), (Type::table(), Type::table()), (Type::record(), Type::record()) ])
                    .required("key", SyntaxShape::String, "Key for the MAC")
                    .named("size", SyntaxShape::Int, "Output size in bytes. Default is 32", Some('s'))
                    .switch("binary", "Output binary instead of hexadecimal representation", Some('b'))
                    .rest("rest", SyntaxShape::CellPath, "Optionally hash data by cell path")
            }

            fn examples(&self) -> Vec<Example<'_>> {
                vec![ Example { description: "Generate a MAC with a specific key and 32-byte output", example: $example, result: None } ]
            }

            fn run(&self, _p: &HashesPlugin, engine: &EngineInterface, call: &EvaluatedCall, input: PipelineData) -> Result<PipelineData, LabeledError> {
                let head = call.head;
                let binary = call.has_flag("binary")?;
                let key: String = call.req(0)?;
                let size = match call.get_flag::<i64>("size")? {
                    Some(s) if s > 0 => s as usize,
                    Some(_) => return Err(LabeledError::new("Size must be greater than 0").with_label("Invalid size", head)),
                    None => 32,
                };
                let cell_paths: Vec<CellPath> = call.rest(1)?;
                let cell_paths = cell_paths.is_empty().not().then_some(cell_paths);

                if let PipelineData::ByteStream(stream, ..) = input {
                    use tiny_keccak::{Hasher, IntoXof, Xof};
                    let mut hasher = $init_path(key.as_bytes(), b"");

                    struct WriteTK<'a, T>(&'a mut T);
                    impl<'a, T: Hasher> std::io::Write for WriteTK<'a, T> {
                        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                            self.0.update(buf);
                            Ok(buf.len())
                        }
                        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
                    }

                    stream.write_to(&mut WriteTK(&mut hasher))?;

                    let mut xof = hasher.into_xof();
                    let mut buf = vec![0u8; size];
                    xof.squeeze(&mut buf);

                    if binary { Ok(Value::binary(buf, head).into_pipeline_data()) }
                    else { Ok(Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), head).into_pipeline_data()) }
                } else {
                    operate($fn_name, $arg_struct_name { binary, cell_paths, size, key }, input, head, engine.signals()).map_err(Into::into)
                }
            }
        }

        fn $fn_name(input: &Value, args: &$arg_struct_name, span: Span) -> Value {
            let (bytes, span) = match input {
                Value::String { val, .. } => (val.as_bytes(), span),
                Value::Binary { val, .. } => (val.as_slice(), span),
                Value::Error { .. } => return input.clone(),
                other => return Value::error(ShellError::OnlySupportsThisInputType { exp_input_type: "string or binary".into(), wrong_type: other.get_type().to_string(), dst_span: span, src_span: other.span() }, span),
            };

            use tiny_keccak::{Hasher, IntoXof, Xof};
            let mut hasher = $init_path(args.key.as_bytes(), b"");
            hasher.update(bytes);
            let mut xof = hasher.into_xof();
            let mut buf = vec![0u8; args.size];
            xof.squeeze(&mut buf);

            if args.binary { Value::binary(buf, span) }
            else { Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), span) }
        }
    };
}

#[cfg(feature = "kmac")]
implement_tk_kmac!("hash kmac128", Kmac128Command, Kmac128Args, kmac128_action, "Generate a KMAC128 authentication code.", "'hello world' | hash kmac128 'my_secret_key'", tiny_keccak::Kmac::v128);

#[cfg(feature = "kmac")]
implement_tk_kmac!("hash kmac256", Kmac256Command, Kmac256Args, kmac256_action, "Generate a KMAC256 authentication code.", "'hello world' | hash kmac256 'my_secret_key'", tiny_keccak::Kmac::v256);


// ==========================================
// --- PARALLEL-HASH ALGORITHMS ---
// ==========================================

macro_rules! implement_tk_parallel {
    ($cmd_name:literal, $struct_name:ident, $arg_struct_name:ident, $fn_name:ident, $desc:literal, $example:literal, $init_path:path) => {
        pub struct $struct_name;

        struct $arg_struct_name {
            cell_paths: Option<Vec<CellPath>>,
            binary: bool,
            size: usize,
            block_size: usize,
        }

        impl CmdArgument for $arg_struct_name {
            fn take_cell_paths(&mut self) -> Option<Vec<CellPath>> { self.cell_paths.take() }
        }

        impl PluginCommand for $struct_name {
            type Plugin = HashesPlugin;
            fn name(&self) -> &str { $cmd_name }
            fn description(&self) -> &str { $desc }

            fn signature(&self) -> Signature {
                Signature::build(self.name())
                    .category(Category::Hash)
                    .input_output_types(vec![ (Type::Binary, Type::Any), (Type::String, Type::Any), (Type::table(), Type::table()), (Type::record(), Type::record()) ])
                    .named("size", SyntaxShape::Int, "Output size in bytes. Default is 32", Some('s'))
                    .named("block-size", SyntaxShape::Int, "Block size in bytes. Default is 8192", None)
                    .switch("binary", "Output binary instead of hexadecimal representation", Some('b'))
                    .rest("rest", SyntaxShape::CellPath, "Optionally hash data by cell path")
            }

            fn examples(&self) -> Vec<Example<'_>> {
                vec![ Example { description: "Hash a value using ParallelHash", example: $example, result: None } ]
            }

            fn run(&self, _p: &HashesPlugin, engine: &EngineInterface, call: &EvaluatedCall, input: PipelineData) -> Result<PipelineData, LabeledError> {
                let head = call.head;
                let binary = call.has_flag("binary")?;
                let size = match call.get_flag::<i64>("size")? {
                    Some(s) if s > 0 => s as usize,
                    Some(_) => return Err(LabeledError::new("Size must be greater than 0").with_label("Invalid size", head)),
                    None => 32,
                };
                let block_size = match call.get_flag::<i64>("block-size")? {
                    Some(s) if s > 0 => s as usize,
                    Some(_) => return Err(LabeledError::new("Block size must be greater than 0").with_label("Invalid block size", head)),
                    None => 8192,
                };
                let cell_paths: Vec<CellPath> = call.rest(0)?;
                let cell_paths = cell_paths.is_empty().not().then_some(cell_paths);

                if let PipelineData::ByteStream(stream, ..) = input {
                    use tiny_keccak::{Hasher, IntoXof, Xof};
                    let mut hasher = $init_path(b"", block_size);

                    struct WriteTK<'a, T>(&'a mut T);
                    impl<'a, T: Hasher> std::io::Write for WriteTK<'a, T> {
                        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                            self.0.update(buf);
                            Ok(buf.len())
                        }
                        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
                    }

                    stream.write_to(&mut WriteTK(&mut hasher))?;

                    let mut xof = hasher.into_xof();
                    let mut buf = vec![0u8; size];
                    xof.squeeze(&mut buf);

                    if binary { Ok(Value::binary(buf, head).into_pipeline_data()) }
                    else { Ok(Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), head).into_pipeline_data()) }
                } else {
                    operate($fn_name, $arg_struct_name { binary, cell_paths, size, block_size }, input, head, engine.signals()).map_err(Into::into)
                }
            }
        }

        fn $fn_name(input: &Value, args: &$arg_struct_name, span: Span) -> Value {
            let (bytes, span) = match input {
                Value::String { val, .. } => (val.as_bytes(), span),
                Value::Binary { val, .. } => (val.as_slice(), span),
                Value::Error { .. } => return input.clone(),
                other => return Value::error(ShellError::OnlySupportsThisInputType { exp_input_type: "string or binary".into(), wrong_type: other.get_type().to_string(), dst_span: span, src_span: other.span() }, span),
            };

            use tiny_keccak::{Hasher, IntoXof, Xof};
            let mut hasher = $init_path(b"", args.block_size);
            hasher.update(bytes);
            let mut xof = hasher.into_xof();
            let mut buf = vec![0u8; args.size];
            xof.squeeze(&mut buf);

            if args.binary { Value::binary(buf, span) }
            else { Value::string(buf.iter().map(|b| format!("{:02x}", b)).collect::<String>(), span) }
        }
    };
}

#[cfg(feature = "parallel_hash")]
implement_tk_parallel!("hash parallel-hash128", ParallelHash128Command, ParallelHash128Args, parallel128_action, "Hash a value using the ParallelHash128 XOF.", "'hello world' | hash parallel-hash128 --block-size 4096", tiny_keccak::ParallelHash::v128);

#[cfg(feature = "parallel_hash")]
implement_tk_parallel!("hash parallel-hash256", ParallelHash256Command, ParallelHash256Args, parallel256_action, "Hash a value using the ParallelHash256 XOF.", "'hello world' | hash parallel-hash256 --block-size 4096", tiny_keccak::ParallelHash::v256);
