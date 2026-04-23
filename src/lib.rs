mod commands_generated;
mod hasher;
mod hashers_generated;
mod special_hashers;

use nu_plugin::Plugin;

pub struct HashesPlugin;

impl Plugin for HashesPlugin {
  fn version(&self) -> String {
    env!("CARGO_PKG_VERSION").into()
  }

  fn commands(&self) -> Vec<Box<dyn nu_plugin::PluginCommand<Plugin = Self>>> {
    let mut cmds = commands_generated::commands();
    
    #[cfg(feature = "blake2")]
    cmds.push(Box::new(special_hashers::Blake2bVarCommand));

    #[cfg(feature = "sha1-checked")]
    cmds.push(Box::new(special_hashers::Sha1CheckedCommand));

    #[cfg(feature = "cshake")]
    {
      cmds.push(Box::new(special_hashers::CShake128Command));
      cmds.push(Box::new(special_hashers::CShake256Command));
    }

    #[cfg(feature = "k12")]
    cmds.push(Box::new(special_hashers::KangarooTwelveCommand));

    #[cfg(feature = "tuple_hash")]
    {
      cmds.push(Box::new(special_hashers::TupleHash128Command));
      cmds.push(Box::new(special_hashers::TupleHash256Command));
    }

    #[cfg(feature = "parallel_hash")]
    {
      cmds.push(Box::new(special_hashers::ParallelHash128Command));
      cmds.push(Box::new(special_hashers::ParallelHash256Command));
    }

    #[cfg(feature = "kmac")]
    {
      cmds.push(Box::new(special_hashers::Kmac128Command));
      cmds.push(Box::new(special_hashers::Kmac256Command));
    }

    cmds
  }
}
