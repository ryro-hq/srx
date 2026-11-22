//! Every format tag Syrox writes, hashes or compares, in one place.
//!
//! A format tag names the encoding of bytes that cross a boundary: a record on
//! disk, a message between processes, a hash domain or a published identity.
//! Each [`Format`] states which boundary it crosses, which module owns it and
//! which older tags its reader still accepts. `cargo xtask formats` renders
//! [`ALL`] into `docs/formats.md`, and `cargo xtask check` rejects versioned tag
//! literals outside this file.
//!
//! Tags are byte-exact. Changing one here changes every record, message and
//! digest that uses it, so a tag changes only together with a deliberate format
//! version bump. A tagged record carries no second version inside its body:
//! the tag alone identifies the format. Companion constants hold the exact terminated forms written
//! by their owners (for example the header line with its `\n`), so call sites
//! never rebuild them by hand.

/// Where the bytes behind a tag travel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    /// Written to disk and read back later, possibly by another version.
    Persisted,
    /// Exchanged between cooperating processes or helpers during one operation.
    Wire,
    /// Only fed to a hasher; the tag separates digest domains and is never stored as text.
    HashDomain,
    /// Part of a published content identity, catalog entry or contract name.
    Identity,
}

impl Boundary {
    /// Name used in the generated reference.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Persisted => "persisted",
            Self::Wire => "wire",
            Self::HashDomain => "hash domain",
            Self::Identity => "identity",
        }
    }
}

/// One format tag and the contract around it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    /// Current tag, without terminator, as written by its owner.
    pub tag: &'static str,
    /// Where bytes carrying the tag travel.
    pub boundary: Boundary,
    /// Module that writes and reads the tag.
    pub owner: &'static str,
    /// Older tags of the same format that the reader still accepts.
    pub reads: &'static [&'static str],
    /// One-line description.
    pub summary: &'static str,
}

macro_rules! registry {
    ($(
        $name:ident = $tag:literal {
            boundary: $boundary:ident,
            owner: $owner:literal,
            summary: $summary:literal
            $(, forms { $($form:ident = $($prefix:literal +)? tag $(+ $suffix:literal)?),+ $(,)? })?
            $(, reads { $($old:ident = $old_tag:literal $({ $($old_form:ident = tag + $old_suffix:literal),+ $(,)? })?),+ $(,)? })?
            $(,)?
        }
    )*) => {
        $(
            #[doc = $summary]
            pub const $name: Format = Format {
                tag: $tag,
                boundary: Boundary::$boundary,
                owner: $owner,
                reads: &[$($($old_tag),+)?],
                summary: $summary,
            };
            $($(
                #[doc = concat!("Exact bytes of [`", stringify!($name), "`] as its owner writes them.")]
                pub const $form: &str = concat!($($prefix,)? $tag $(, $suffix)?);
            )+)?
            $($(
                #[doc = concat!("Older tag of [`", stringify!($name), "`] that its reader still accepts.")]
                pub const $old: &str = $old_tag;
                $($(
                    #[doc = concat!("Exact bytes of [`", stringify!($old), "`] as its owner writes them.")]
                    pub const $old_form: &str = concat!($old_tag, $old_suffix);
                )+)?
            )+)?
        )*

        /// Every registered format, grouped by owning crate and module.
        pub const ALL: &[&Format] = &[$(&$name),*];
    };
}

registry! {
    // syrox_engine::project
    LOCK = "syrox-lock" {
        boundary: Persisted,
        owner: "syrox_engine::project::lock",
        summary: "Project lock. Every section is always written: inputs, standard library, project edges (including GitHub pins) and assets.",
    }
    STD_DIGEST = "syrox-std" {
        boundary: HashDomain,
        owner: "syrox_engine::project::lock",
        summary: "Length-framed domain of the standard library digest bound by a lock.",
    }
    INPUT_DIGEST = "syrox-input" {
        boundary: HashDomain,
        owner: "syrox_engine::project::lock",
        summary: "Length-framed domain of one locked input's digest.",
    }
    PROJECT_DIGEST = "syrox-project" {
        boundary: HashDomain,
        owner: "syrox_engine::project::lock",
        summary: "Length-framed domain of the locked project digest.",
    }

    // syrox_engine::catalog
    ARTIFACT_RECIPE = "syrox-artifact-recipe" {
        boundary: Identity,
        owner: "syrox_engine::catalog::artifacts",
        summary: "First element of the JSON array that identifies a catalog artifact recipe.",
    }

    // syrox_engine::store
    STORE = "syrox-store" {
        boundary: Persisted,
        owner: "syrox_engine::store",
        summary: "Store format marker at `.syrox-store/format`; a Store without it was written by an earlier srx.",
        forms { STORE_LINE = tag + "\n" },
    }
    STORE_ROOT = "syrox-root" {
        boundary: Persisted,
        owner: "syrox_engine::store",
        summary: "Store root record listing the objects a named root retains.",
        forms { STORE_ROOT_LINE = tag + "\n" },
    }
    CHUNKED_ARTIFACT = "syrox-chunked-artifact" {
        boundary: Persisted,
        owner: "syrox_engine::store::chunked",
        summary: "Manifest of an artifact stored as fixed-size chunks.",
        forms { CHUNKED_ARTIFACT_LINE = tag + "\n" },
    }
    INTEREST = "syrox-interest" {
        boundary: Persisted,
        owner: "syrox_engine::store::retention",
        summary: "Retention interest record that keeps roots alive across collection.",
        forms { INTEREST_LINE = tag + "\n" },
    }
    DURABLE_INTEREST = "syrox-durable-interest" {
        boundary: Persisted,
        owner: "syrox_engine::store::retention::durable",
        summary: "Durable retention interest that survives the process that created it.",
        forms { DURABLE_INTEREST_LINE = tag + "\n" },
    }
    DURABLE_STORE_ANCHOR = "syrox-durable-store-anchor" {
        boundary: HashDomain,
        owner: "syrox_engine::store::retention::durable",
        summary: "Digest of the Store directory identities a durable interest was opened against.",
        forms { DURABLE_STORE_ANCHOR_LINE = tag + "\n" },
    }

    // syrox_engine::result
    PACKAGE_RESULT = "syrox-package-result" {
        boundary: Persisted,
        owner: "syrox_engine::result",
        summary: "Result manifest of an ordinary package build, capped at 1 MiB.",
        forms { PACKAGE_RESULT_LINE = tag + "\n" },
    }
    SYSTEM_RESULT = "syrox-system-result" {
        boundary: Persisted,
        owner: "syrox_engine::result",
        summary: "Result manifest of a system build, with its admitted budget and chunked outputs.",
        forms { SYSTEM_RESULT_LINE = tag + "\n" },
    }
    ARTIFACT = "syrox-artifact" {
        boundary: Persisted,
        owner: "syrox_engine::result::artifact",
        summary: "Single-file artifact encoding stored as a result output.",
        forms { ARTIFACT_LINE = tag + "\n" },
    }
    SYSTEM_WORKER_OUTPUTS = "syrox-system-worker-outputs" {
        boundary: Wire,
        owner: "syrox_engine::result::worker_output",
        summary: "System worker output transfer; the bare tag is also the output protocol named by system build actions.",
        forms { SYSTEM_WORKER_OUTPUTS_LINE = tag + "\n" },
    }
    SYSTEM_OUTPUT_BUDGET = "syrox-system-output-budget" {
        boundary: HashDomain,
        owner: "syrox_engine::result::worker_output",
        summary: "Binding of system worker outputs to the admitted budget.",
        forms { SYSTEM_OUTPUT_BUDGET_LINE = tag + "\n" },
    }

    // syrox_engine::bundle
    RUNTIME_BUNDLE = "syrox-runtime-bundle" {
        boundary: Persisted,
        owner: "syrox_engine::bundle",
        summary: "Exported runtime bundle: a result and its object closure.",
        forms { RUNTIME_BUNDLE_LINE = tag + "\n" },
    }
    SYSTEM_BUNDLE = "syrox-system-bundle" {
        boundary: Persisted,
        owner: "syrox_engine::bundle::system",
        summary: "Exported system result with its complete chunk closure.",
        forms { SYSTEM_BUNDLE_LINE = tag + "\n" },
    }

    // syrox_engine::image
    SYSTEM_IMAGE = "syrox-system-image" {
        boundary: Identity,
        owner: "syrox_engine::image",
        summary: "Initramfs image provenance manifest; its digest identifies the image.",
        forms { SYSTEM_IMAGE_LINE = tag + "\n" },
    }
    INITRAMFS = "syrox-initramfs" {
        boundary: Identity,
        owner: "syrox_engine::image",
        summary: "Archive format named inside the system image manifest.",
    }
    RAW_IMAGE = "syrox-raw-image" {
        boundary: Identity,
        owner: "syrox_engine::image::raw",
        summary: "Raw GPT disk image provenance manifest.",
        forms { RAW_IMAGE_LINE = tag + "\n" },
    }
    QCOW2_IMAGE = "syrox-qcow2-image" {
        boundary: Identity,
        owner: "syrox_engine::image::qcow2",
        summary: "qcow2 disk image metadata manifest.",
        forms { QCOW2_IMAGE_LINE = tag + "\n" },
    }
    VERITY_IMAGE = "syrox-verity-image" {
        boundary: Identity,
        owner: "syrox_engine::image::verity",
        summary: "dm-verity image parameter manifest.",
        forms { VERITY_IMAGE_LINE = tag + "\n" },
    }

    // syrox_engine::build
    BUILD_PROGRAM = "SRXBUILD" {
        boundary: Identity,
        owner: "syrox_engine::build::program",
        summary: "Binary build program encoding; the magic is followed by version byte 0x01.",
        forms { BUILD_PROGRAM_MAGIC = tag + "\x01" },
    }
    HOST_PROGRAM_PROFILE = "syrox-host-program-x86_64" {
        boundary: Identity,
        owner: "syrox_engine::build",
        summary: "Execution profile of host bootstrap build programs, named in build actions.",
    }
    MANAGED_PROGRAM_PROFILE = "syrox-managed-program-x86_64" {
        boundary: Identity,
        owner: "syrox_engine::build",
        summary: "Execution profile of managed build programs, named in build actions.",
    }
    BUILD_ACTION = "syrox-build-action" {
        boundary: Identity,
        owner: "syrox_engine::build::records",
        summary: "Build action record; its digest keys the build cache.",
    }
    BUILD_RESULT = "syrox-build-result" {
        boundary: Persisted,
        owner: "syrox_engine::build::records",
        summary: "Build receipt binding an action to its published outputs.",
        forms { BUILD_RESULT_LINE = tag + "\n" },
    }
    BUILD_INDEX = "syrox-build-index" {
        boundary: Persisted,
        owner: "syrox_engine::build::cache",
        summary: "Action index entry listing cached receipts for one action.",
    }
    BUILD_CLOSING = "syrox-build-closing" {
        boundary: Persisted,
        owner: "syrox_engine::build::shared",
        summary: "Journal marker that a shared build is closing.",
        forms { BUILD_CLOSING_LINE = tag + "\n" },
    }
    BUILD_ATTEMPT = "syrox-build-attempt" {
        boundary: Persisted,
        owner: "syrox_engine::build::journal",
        summary: "Build journal attempt record: action and timeout.",
    }
    BUILD_AUTHORIZED = "syrox-build-authorized" {
        boundary: Persisted,
        owner: "syrox_engine::build::journal",
        summary: "Build journal marker that an attempt was authorized.",
        forms { BUILD_AUTHORIZED_LINE = tag + "\n" },
    }
    BUILD_REVOKED = "syrox-build-revoked" {
        boundary: Persisted,
        owner: "syrox_engine::build::journal",
        summary: "Build journal marker that an authorization was revoked.",
        forms { BUILD_REVOKED_LINE = tag + "\n" },
    }
    BUILD_CLEANED = "syrox-build-cleaned" {
        boundary: Persisted,
        owner: "syrox_engine::build::journal",
        summary: "Build journal marker that attempt resources were cleaned.",
        forms { BUILD_CLEANED_LINE = tag + "\n" },
    }
    BUILD_OUTCOME = "syrox-build-outcome" {
        boundary: Persisted,
        owner: "syrox_engine::build::journal",
        summary: "Build journal outcome: published receipt or failure.",
        forms { BUILD_OUTCOME_LINE = tag + "\n" },
    }
    BUILD_CGROUP = "syrox-build-cgroup" {
        boundary: Persisted,
        owner: "syrox_engine::build::journal",
        summary: "Build journal record of the attempt's cgroup.",
        forms { BUILD_CGROUP_LINE = tag + "\n" },
    }
    BUILD_OPERATION = "syrox-build-operation" {
        boundary: Persisted,
        owner: "syrox_engine::build::journal",
        summary: "Build journal operation identity: name, boot and owners.",
        forms { BUILD_OPERATION_LINE = tag + "\n" },
    }
    BUILD_ORIGIN = "syrox-build-origin" {
        boundary: Persisted,
        owner: "syrox_engine::build::bootstrap::linux",
        summary: "Origin of a bootstrap build: lock, package, domain and path.",
        forms { BUILD_ORIGIN_LINE = tag + "\n" },
    }
    HOST_TOOLCHAIN = "syrox-host-toolchain" {
        boundary: Identity,
        owner: "syrox_engine::build::bootstrap::linux::inventory",
        summary: "Host toolchain inventory whose digest pins bootstrap builds.",
        forms { HOST_TOOLCHAIN_LINE = tag + "\n" },
    }
    OUTPUT_GROUP = "syrox-output-group" {
        boundary: Persisted,
        owner: "syrox_engine::build::bootstrap::group",
        summary: "Framed group of named bootstrap outputs.",
        forms { OUTPUT_GROUP_LINE = tag + "\n" },
    }
    MANAGED_BUILD_HELLO = "syrox-managed-build-hello" {
        boundary: Wire,
        owner: "syrox_engine::build::managed::handshake",
        summary: "Managed build worker hello.",
        forms { MANAGED_BUILD_HELLO_LINE = tag + "\n" },
    }
    MANAGED_BUILD_RESOURCES = "syrox-managed-build-resources" {
        boundary: Wire,
        owner: "syrox_engine::build::managed::transfer",
        summary: "Managed build resource offer.",
        forms { MANAGED_BUILD_RESOURCES_LINE = tag + "\n" },
    }
    MANAGED_BUILD_RESOURCE_BATCH = "syrox-managed-build-resource-batch" {
        boundary: Wire,
        owner: "syrox_engine::build::managed::transfer",
        summary: "Managed build resource descriptor batch.",
        forms { MANAGED_BUILD_RESOURCE_BATCH_LINE = tag + "\n" },
    }
    MANAGED_BUILD_NAMESPACE_PROCESSED = "syrox-managed-build-namespace-processed" {
        boundary: Wire,
        owner: "syrox_engine::build::managed::namespace_protocol",
        summary: "Managed build namespace preparation report.",
        forms { MANAGED_BUILD_NAMESPACE_PROCESSED_LINE = tag + "\n" },
    }
    MANAGED_BUILD_COMMIT = "syrox-managed-build-commit" {
        boundary: Wire,
        owner: "syrox_engine::build::managed::namespace_protocol::execution",
        summary: "Coordinator commit that lets a managed build start.",
        forms { MANAGED_BUILD_COMMIT_LINE = tag + "\n" },
    }
    MANAGED_BUILD_EXIT = "syrox-managed-build-exit" {
        boundary: Wire,
        owner: "syrox_engine::build::managed::namespace_protocol::execution",
        summary: "Managed build exit report.",
        forms { MANAGED_BUILD_EXIT_LINE = tag + "\n" },
    }
    MANAGED_BUILD_EXIT_OBSERVED = "syrox-managed-build-exit-observed" {
        boundary: Wire,
        owner: "syrox_engine::build::managed::namespace_protocol::execution",
        summary: "Coordinator acknowledgment of an observed managed build exit.",
        forms { MANAGED_BUILD_EXIT_OBSERVED_LINE = tag + "\n" },
    }
    MANAGED_BUILD_RETENTION_PROCESSED = "syrox-managed-build-retention-processed" {
        boundary: Wire,
        owner: "syrox_engine::build::managed::retention_protocol",
        summary: "Managed build retention preparation report.",
        forms { MANAGED_BUILD_RETENTION_PROCESSED_LINE = tag + "\n" },
    }
    MANAGED_BUILD_RETENTION_OBSERVED = "syrox-managed-build-retention-observed" {
        boundary: Wire,
        owner: "syrox_engine::build::managed::retention_protocol",
        summary: "Coordinator observation of managed build retention.",
        forms { MANAGED_BUILD_RETENTION_OBSERVED_LINE = tag + "\n" },
    }
    SYSTEM_MANAGED_PROFILE = "syrox-system-managed-x86_64" {
        boundary: Identity,
        owner: "syrox_engine::build::system::records",
        summary: "Execution profile named by system build actions.",
    }
    SYSTEM_BUILD_ACTION = "syrox-system-build-action" {
        boundary: Identity,
        owner: "syrox_engine::build::system::records",
        summary: "System build action record; its digest identifies the action.",
        forms { SYSTEM_BUILD_ACTION_LINE = tag + "\n" },
    }
    SYSTEM_BUILD_PAYLOAD = "syrox-system-build-payload" {
        boundary: Persisted,
        owner: "syrox_engine::build::system::namespace",
        summary: "System build namespace payload record.",
        forms { SYSTEM_BUILD_PAYLOAD_LINE = tag + "\n" },
    }
    SYSTEM_INPUT_RESOURCES = "syrox-system-input-resources" {
        boundary: Wire,
        owner: "syrox_engine::build::system::resources",
        summary: "Canonical system build input resource record.",
        forms { SYSTEM_INPUT_RESOURCES_LINE = tag + "\n" },
    }
    SYSTEM_INPUT_READY = "syrox-system-input-ready" {
        boundary: Wire,
        owner: "syrox_engine::build::system::input_transfer",
        summary: "System input receiver readiness.",
        forms { SYSTEM_INPUT_READY_LINE = tag + "\n" },
    }
    SYSTEM_INPUT_MANIFEST = "syrox-system-input-manifest" {
        boundary: Wire,
        owner: "syrox_engine::build::system::input_transfer",
        summary: "System input metadata fragment.",
        forms { SYSTEM_INPUT_MANIFEST_LINE = tag + "\n" },
    }
    SYSTEM_INPUT_BATCH = "syrox-system-input-batch" {
        boundary: Wire,
        owner: "syrox_engine::build::system::input_transfer",
        summary: "System input descriptor batch.",
        forms { SYSTEM_INPUT_BATCH_LINE = tag + "\n" },
    }
    SYSTEM_INPUT_ACCEPTED = "syrox-system-input-accepted" {
        boundary: Wire,
        owner: "syrox_engine::build::system::input_transfer",
        summary: "System input batch acceptance.",
        forms { SYSTEM_INPUT_ACCEPTED_LINE = tag + "\n" },
    }

    // syrox_engine::deployment
    GENERATION = "syrox-generation" {
        boundary: Persisted,
        owner: "syrox_engine::deployment::manifest",
        summary: "Deployment generation manifest.",
        forms { GENERATION_LINE = tag + "\n" },
    }
    SHELL_SESSION = "syrox-shell-session" {
        boundary: Persisted,
        owner: "syrox_engine::deployment::manifest",
        summary: "Shell session generation manifest.",
        forms { SHELL_SESSION_LINE = tag + "\n" },
    }
    SHELL_COMMAND_INDEX = "syrox-shell-command-index" {
        boundary: HashDomain,
        owner: "syrox_engine::deployment::manifest::commands",
        summary: "Shell command exposure index; only its digest leaves the coordinator.",
        forms { SHELL_COMMAND_INDEX_LINE = tag + "\n" },
    }
    SHELL_OPERATION = "syrox-shell-operation" {
        boundary: Persisted,
        owner: "syrox_engine::deployment::shell::managed::record",
        summary: "Managed Shell operation record with its session snapshot.",
        forms { SHELL_OPERATION_LINE = tag + "\n" },
    }
    SERVICES_INSTALLATION = "syrox-services-installation" {
        boundary: Persisted,
        owner: "syrox_engine::deployment::services::installation",
        summary: "Services installation identity file.",
        forms { SERVICES_INSTALLATION_LINE = tag + "\n" },
    }
    SERVICES_CANDIDATE = "syrox-services-candidate" {
        boundary: Persisted,
        owner: "syrox_engine::deployment::services::installation",
        summary: "Services installation candidate record.",
        forms { SERVICES_CANDIDATE_LINE = tag + "\n" },
    }
    GENERATION_ROOT = "syrox-generation-root" {
        boundary: HashDomain,
        owner: "syrox_engine::deployment::services::installation",
        summary: "Digest that names the Store root of one generation role.",
        forms { GENERATION_ROOT_LINE = tag + "\n" },
    }
    SERVICES_ACTIVATION = "syrox-services-activation" {
        boundary: Persisted,
        owner: "syrox_engine::deployment::services::activation",
        summary: "Services activation record.",
        forms { SERVICES_ACTIVATION_LINE = tag + "\n" },
    }
    SERVICES_LAUNCH = "syrox-services-launch" {
        boundary: Persisted,
        owner: "syrox_engine::deployment::services::launch_binding",
        summary: "Binding of a Services invocation to its generation, process and context.",
        forms { SERVICES_LAUNCH_LINE = tag + "\n" },
    }
    SERVICES_SCOPE = "syrox-services-scope" {
        boundary: Identity,
        owner: "syrox_engine::deployment::services::launch_binding",
        summary: "Prefix of the scope key derived from a Services manager context, written as `tag:digest`.",
    }
    SERVICES_RELOAD_TARGET = "syrox-services-reload-target" {
        boundary: HashDomain,
        owner: "syrox_engine::deployment::services::apply::manager",
        summary: "Identity of the desired rendered unit batch.",
        forms { SERVICES_RELOAD_TARGET_LINE = tag + "\n" },
    }
    UNIT_OWNERSHIP = "syrox-unit-ownership" {
        boundary: Persisted,
        owner: "syrox_engine::deployment::services::unit_files",
        summary: "Ledger of unit files published by Services.",
        forms { UNIT_OWNERSHIP_LINE = tag + "\n" },
    }
    SERVICES_UNIT = "syrox-services-unit" {
        boundary: Persisted,
        owner: "syrox_engine::deployment::services::unit_files",
        summary: "Comment marker on the first line of every unit file rendered by Services.",
        forms { SERVICES_UNIT_MARKER = "# " + tag + "\n" },
    }

    // syrox_engine::systemd
    SYSTEMD_CONTRACT = "syrox-systemd" {
        boundary: Identity,
        owner: "syrox_engine::systemd::contract",
        summary: "Identifier of the systemd interface contract.",
    }
    SYSTEMD_MANAGER = "syrox-systemd-manager" {
        boundary: HashDomain,
        owner: "syrox_engine::systemd",
        summary: "Fingerprint of a systemd manager: scope, bus GUID and owner.",
        forms { SYSTEMD_MANAGER_LINE = tag + "\n" },
    }
    OBSERVED_BUILD_UNIT = "syrox-observed-build-unit" {
        boundary: HashDomain,
        owner: "syrox_engine::systemd::build",
        summary: "Observation of a managed build unit.",
        forms { OBSERVED_BUILD_UNIT_LINE = tag + "\n" },
    }
    OBSERVED_SHELL_SERVICE = "syrox-observed-shell-service" {
        boundary: HashDomain,
        owner: "syrox_engine::systemd::service",
        summary: "Observation of a Shell service unit.",
        forms { OBSERVED_SHELL_SERVICE_LINE = tag + "\n" },
    }
    LOADED_SERVICES_UNIT = "syrox-loaded-services-unit" {
        boundary: HashDomain,
        owner: "syrox_engine::systemd::loaded",
        summary: "Observation of a loaded Services unit.",
        forms { LOADED_SERVICES_UNIT_LINE = tag + "\n" },
    }

    // syrox_engine::runtime
    COMMAND_EXECUTION = "syrox-command-execution" {
        boundary: Wire,
        owner: "syrox_engine::runtime::command_proxy::launch_contract",
        summary: "Domain of command execution metadata, written as its JSON `domain` field.",
    }
    COMMAND_ROOT_ARGUMENTS = "syrox-command-root-arguments" {
        boundary: HashDomain,
        owner: "syrox_engine::runtime::command_proxy::launch_contract",
        summary: "Pin of a command root's arguments.",
        forms { COMMAND_ROOT_ARGUMENTS_LINE = tag + "\n" },
    }
    SHELL_COMMAND_REQUEST = "syrox-shell-command-request" {
        boundary: Wire,
        owner: "syrox_engine::runtime::command_proxy::request",
        summary: "Shell command request sent to the command broker.",
        forms { SHELL_COMMAND_REQUEST_LINE = tag + "\n" },
    }
    COMMAND_GUARDIAN = "syrox-command-guardian" {
        boundary: Wire,
        owner: "syrox_engine::runtime::command_proxy::guardian",
        summary: "Command guardian event frame.",
        forms { COMMAND_GUARDIAN_LINE = tag + "\n" },
    }

    // syrox_engine::execution
    COMMAND_MONITOR = "syrox-command-monitor" {
        boundary: Wire,
        owner: "syrox_engine::execution::command_evidence",
        summary: "Domain of command monitor introductions, written as their JSON `domain` field.",
    }
    COMMAND_MONITOR_ACK = "syrox-command-monitor-ack" {
        boundary: Wire,
        owner: "syrox_engine::execution::command_evidence",
        summary: "Acknowledgment of a command monitor introduction, written as `tag digest`.",
    }
    SESSION_STATE = "syrox-session-state" {
        boundary: Persisted,
        owner: "syrox_engine::execution::journal",
        summary: "Execution session journal state.",
        forms { SESSION_STATE_LINE = tag + "\n" },
    }
    SERVICE_ROLE = "syrox-service-role" {
        boundary: HashDomain,
        owner: "syrox_engine::execution::journal::roles",
        summary: "Stable pin of a service role.",
        forms { SERVICE_ROLE_LINE = tag + "\n" },
    }
    SERVICE_BODY = "syrox-service-body" {
        boundary: Wire,
        owner: "syrox_engine::execution::resources",
        summary: "Managed service specification body.",
        forms { SERVICE_BODY_LINE = tag + "\n" },
    }
    SERVICE_OFFER = "syrox-service-offer" {
        boundary: Wire,
        owner: "syrox_engine::execution::resources::transfer",
        summary: "Service resource transfer offer.",
        forms { SERVICE_OFFER_LINE = tag + "\n" },
    }
    SERVICE_CHUNK = "syrox-service-chunk" {
        boundary: Wire,
        owner: "syrox_engine::execution::resources::transfer",
        summary: "Service resource transfer chunk.",
        forms { SERVICE_CHUNK_LINE = tag + "\n" },
    }
    SERVICE_RESOURCES = "syrox-service-resources" {
        boundary: Wire,
        owner: "syrox_engine::execution::resources::transfer",
        summary: "Service resource descriptors message; the bare tag without terminator.",
    }
    OWNER_PROTOCOL = "syrox-owner" {
        boundary: Wire,
        owner: "syrox_engine::execution::launcher",
        summary: "Owner coordinator messages, written as `tag verb`.",
        forms {
            OWNER_RETENTION = tag + " retention",
            OWNER_PROCESSED = tag + " processed",
            OWNER_COMMIT = tag + " commit",
            OWNER_CLOSE = tag + " close",
        },
    }
    SERVICE_PROTOCOL = "syrox-service" {
        boundary: Wire,
        owner: "syrox_engine::execution::launcher::service",
        summary: "Managed service launcher messages, written as `tag verb`.",
        forms {
            SERVICE_PROCESSED = tag + " processed",
            SERVICE_NAMESPACE = tag + " namespace",
            SERVICE_COMMIT = tag + " commit",
            SERVICE_DENIED = tag + " denied",
        },
    }

    // syrox_engine::platform
    TERMINAL_ATTRIBUTES = "syrox-terminal-attributes" {
        boundary: HashDomain,
        owner: "syrox_engine::platform::linux::fd::terminal",
        summary: "Fingerprint of meaningful terminal attribute fields.",
        forms { TERMINAL_ATTRIBUTES_NUL = tag + "\0" },
    }

    // syrox_system
    SYSTEM_TREE = "syrox-system-tree" {
        boundary: Identity,
        owner: "syrox_system::image",
        summary: "Canonical system tree metadata; the encoding defines the tree's SHA-256 identity.",
        forms { SYSTEM_TREE_LINE = tag + "\n" },
    }
    SYSTEM_INVENTORY = "syrox-system-inventory" {
        boundary: HashDomain,
        owner: "syrox_system::inventory",
        summary: "Fingerprint of a system inventory observation.",
        forms { SYSTEM_INVENTORY_LINE = tag + "\n" },
    }
    FILESYSTEM_OBSERVATION = "syrox-filesystem-observation" {
        boundary: HashDomain,
        owner: "syrox_system::filesystem",
        summary: "Fingerprint of one filesystem observation, including capacity and usage.",
        forms { FILESYSTEM_OBSERVATION_LINE = tag + "\n" },
    }
    BUILDER_LIMITS = "syrox-builder-limits" {
        boundary: HashDomain,
        owner: "syrox_system::budget",
        summary: "Fingerprint of the builder resource ceilings.",
        forms { BUILDER_LIMITS_LINE = tag + "\n" },
    }
    SYSTEM_WORKSPACE_LAYOUT = "syrox-system-workspace-layout" {
        boundary: HashDomain,
        owner: "syrox_system::workspace",
        summary: "Identity of a scratch/output workspace geometry.",
        forms { SYSTEM_WORKSPACE_LAYOUT_LINE = tag + "\n" },
    }
    PRIVATE_SCRATCH_ACTIVATION = "syrox-private-scratch-activation" {
        boundary: Persisted,
        owner: "syrox_system::helper_activation",
        summary: "Comment marker on the first line of the helper socket and service units.",
        forms { PRIVATE_SCRATCH_ACTIVATION_MARKER = "# " + tag + "\n" },
    }
    PRIVATE_SCRATCH_AUTHORIZATION = "syrox-private-scratch-authorization" {
        boundary: HashDomain,
        owner: "syrox_system::helper::session",
        summary: "Authorization digest of a private scratch request.",
        forms { PRIVATE_SCRATCH_AUTHORIZATION_LINE = tag + "\n" },
    }
    PRIVATE_SCRATCH_JOURNAL = "syrox-private-scratch-journal" {
        boundary: HashDomain,
        owner: "syrox_system::helper::recovery::evidence",
        summary: "Digest over the private scratch journal records.",
        forms { PRIVATE_SCRATCH_JOURNAL_LINE = tag + "\n" },
    }
    PRIVATE_SCRATCH_RECOVERY_PLAN = "syrox-private-scratch-recovery-plan" {
        boundary: HashDomain,
        owner: "syrox_system::helper::recovery",
        summary: "Digest of a private scratch recovery plan.",
        forms { PRIVATE_SCRATCH_RECOVERY_PLAN_LINE = tag + "\n" },
    }
    PRIVATE_WORKSPACE_AUTHORIZATION = "syrox-private-workspace-authorization" {
        boundary: HashDomain,
        owner: "syrox_system::helper::workspace",
        summary: "Authorization digest of a private workspace request.",
        forms { PRIVATE_WORKSPACE_AUTHORIZATION_LINE = tag + "\n" },
    }
    PRIVATE_WORKSPACE_RECOVERY_PLAN = "syrox-private-workspace-recovery-plan" {
        boundary: HashDomain,
        owner: "syrox_system::helper::recovery::workspace",
        summary: "Digest of a private workspace recovery plan.",
        forms { PRIVATE_WORKSPACE_RECOVERY_PLAN_LINE = tag + "\n" },
    }

    // syrox
    RELEASE = "syrox-release" {
        boundary: Identity,
        owner: "syrox::cli::commands::install_self",
        summary: "Installed release manifest; its digest names the release.",
        forms { RELEASE_LINE = tag + "\n" },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Family name and version of a tag; an unversioned tag is version 1.
    fn split(tag: &str) -> (&str, u32) {
        tag.rsplit_once("-v")
            .and_then(|(base, version)| Some((base, version.parse().ok()?)))
            .unwrap_or((tag, 1))
    }

    fn well_formed(tag: &str) -> bool {
        if tag == BUILD_PROGRAM.tag {
            return true;
        }
        let Some(name) = tag.strip_prefix("syrox-") else {
            return false;
        };
        let (base, _) = split(name);
        let version = &name[base.len()..];
        !base.is_empty()
            && !base.starts_with('-')
            && !base.ends_with('-')
            && !base.contains("--")
            && base.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte)
            })
            && (version.is_empty()
                || version.strip_prefix("-v").is_some_and(|digits| {
                    // Version 1 is the unversioned tag; `-v1` is never written.
                    !digits.starts_with('0')
                        && digits != "1"
                        && digits.bytes().all(|byte| byte.is_ascii_digit())
                }))
    }

    #[test]
    fn tags_are_unique_across_current_and_older_versions() {
        let mut seen = BTreeSet::new();
        for format in ALL {
            for tag in std::iter::once(&format.tag).chain(format.reads) {
                assert!(seen.insert(*tag), "duplicate tag {tag}");
            }
        }
    }

    #[test]
    fn older_versions_belong_to_the_family_and_precede_the_current_tag() {
        for format in ALL {
            let (base, current) = split(format.tag);
            assert!(
                !format.reads.contains(&format.tag),
                "{}",
                format.tag
            );
            for old in format.reads {
                let (old_base, version) = split(old);
                assert_eq!(
                    old_base, base,
                    "{old} is not a version of {}",
                    format.tag
                );
                assert!(
                    version < current,
                    "{old} is not older than {}",
                    format.tag
                );
            }
        }
    }

    /// Pre-release, no format has a released predecessor: a tag carries a
    /// version suffix only once an earlier tag of its family is still read.
    #[test]
    fn only_formats_with_older_readers_carry_a_version() {
        for format in ALL {
            let versioned = split(format.tag).0 != format.tag;
            assert!(
                !versioned || !format.reads.is_empty(),
                "{} carries a version suffix without an older tag in `reads`",
                format.tag
            );
        }
    }

    #[test]
    fn tags_are_well_formed() {
        for format in ALL {
            for tag in std::iter::once(&format.tag).chain(format.reads) {
                assert!(well_formed(tag), "malformed tag {tag}");
            }
            assert!(!format.summary.is_empty() && !format.summary.contains('\n'));
            assert!(
                format.owner.starts_with("syrox"),
                "{}",
                format.owner
            );
        }
        assert!(!well_formed("syrox-lock-v0"));
        assert!(!well_formed("syrox-lock-v1"));
        assert!(well_formed("syrox-lock-v2"));
        assert!(!well_formed("syrox-lock-v01"));
        assert!(!well_formed("syrox-Lock"));
        assert!(!well_formed("srx-lock"));
    }

    #[test]
    fn critical_tags_keep_their_bytes() {
        assert_eq!(LOCK.tag, "syrox-lock");
        assert!(LOCK.reads.is_empty());
        assert_eq!(GENERATION_LINE.as_bytes(), b"syrox-generation\n");
        assert_eq!(SHELL_SESSION_LINE, "syrox-shell-session\n");
        assert_eq!(
            PACKAGE_RESULT_LINE.as_bytes(),
            b"syrox-package-result\n"
        );
        assert_eq!(
            SYSTEM_RESULT_LINE.as_bytes(),
            b"syrox-system-result\n"
        );
        assert_eq!(STORE_LINE, "syrox-store\n");
        assert_eq!(STORE_ROOT_LINE, "syrox-root\n");
        assert_eq!(BUILD_PROGRAM_MAGIC.as_bytes(), b"SRXBUILD\x01");
        assert_eq!(
            TERMINAL_ATTRIBUTES_NUL.as_bytes(),
            b"syrox-terminal-attributes\0"
        );
        assert_eq!(SERVICES_UNIT_MARKER, "# syrox-services-unit\n");
        assert_eq!(OWNER_RETENTION, "syrox-owner retention");
        assert_eq!(SERVICE_DENIED, "syrox-service denied");
        assert_eq!(SERVICE_RESOURCES.tag, "syrox-service-resources");
    }
}
