//! Aquisição das fontes escolhidas pelo projeto.
//!
//! O pedido fixa os bytes esperados e seu tamanho máximo. HTTPS confere também
//! a identidade do servidor; uma fonte local exige acesso explícito ao diretório.
//! A inspeção de um archive confere seu conteúdo antes de usá-lo no build.

pub mod archive;
pub mod github;
pub mod https;
pub mod local;
