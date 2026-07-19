use crate::policy::dlp::SecretCategory as GwSecretCategory;
use crate::policy::semantic::SemanticFindingType as GwSemanticFindingType;
use dashboard_proto::event::SecretCategory as DpSecretCategory;
use dashboard_proto::event::SemanticFindingType as DpSemanticFindingType;

impl From<&GwSecretCategory> for DpSecretCategory {
    fn from(gw: &GwSecretCategory) -> Self {
        match gw {
            GwSecretCategory::AwsAccessKey => DpSecretCategory::AwsAccessKey,
            GwSecretCategory::GitHubToken => DpSecretCategory::GitHubToken,
            GwSecretCategory::OpenAiApiKey => DpSecretCategory::OpenAiApiKey,
            GwSecretCategory::AnthropicApiKey => DpSecretCategory::AnthropicApiKey,
            GwSecretCategory::SshPrivateKey => DpSecretCategory::SshPrivateKey,
            GwSecretCategory::StripeKey => DpSecretCategory::StripeKey,
            GwSecretCategory::DatabaseUri => DpSecretCategory::DatabaseUri,
            GwSecretCategory::Pii => DpSecretCategory::Pii,
            GwSecretCategory::HighEntropy => DpSecretCategory::HighEntropy,
            GwSecretCategory::CryptoSeedPhrase => DpSecretCategory::CryptoSeedPhrase,
            GwSecretCategory::EnvVar => DpSecretCategory::EnvVar,
            GwSecretCategory::AzureStorageKey => DpSecretCategory::AzureStorageKey,
            GwSecretCategory::GcpApiKey => DpSecretCategory::GcpApiKey,
            GwSecretCategory::SlackToken => DpSecretCategory::SlackToken,
            GwSecretCategory::SendGridKey => DpSecretCategory::SendGridKey,
            GwSecretCategory::CreditCard => DpSecretCategory::CreditCard,
            GwSecretCategory::Other => DpSecretCategory::Other,
        }
    }
}

impl From<&GwSemanticFindingType> for DpSemanticFindingType {
    fn from(gw: &GwSemanticFindingType) -> Self {
        match gw {
            GwSemanticFindingType::ToolDescriptionPoisoning => {
                DpSemanticFindingType::ToolDescriptionPoisoning
            }
            GwSemanticFindingType::ResponseInstructionManipulation => {
                DpSemanticFindingType::ResponseInstructionManipulation
            }
            GwSemanticFindingType::SemanticExfiltration => {
                DpSemanticFindingType::SemanticExfiltration
            }
        }
    }
}
