#![forbid(unsafe_code)]

mod canonical;
mod compiler;
mod error;
mod template;

pub use compiler::{CompiledRulePack, CompiledSiteRule, RuleCompiler};
pub use error::{CompileError, CompileErrors};
pub use template::{TemplateContext, render_identity_template, render_url_template};
