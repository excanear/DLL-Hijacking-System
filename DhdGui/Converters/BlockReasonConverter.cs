using DhdBridge;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace DhdGui.Converters;

[ValueConversion(typeof(BlockReasonManaged), typeof(IEnumerable<string>))]
public sealed class BlockReasonConverter : IValueConverter
{
    private static readonly Dictionary<BlockReasonManaged, string> _labels = new()
    {
        [BlockReasonManaged.PathRelative]          = "Caminho relativo",
        [BlockReasonManaged.PathNotInWhitelist]    = "Caminho não está na whitelist",
        [BlockReasonManaged.PathInBlockedDir]      = "Caminho em diretório bloqueado",
        [BlockReasonManaged.PathIsUnc]             = "Caminho UNC",
        [BlockReasonManaged.SymlinkResolutionFail] = "Falha na resolução de symlink",
        [BlockReasonManaged.NameHomoglyph]         = "Nome com homóglifos suspeitos",
        [BlockReasonManaged.NameTyposquatting]     = "Nome com typosquatting",
        [BlockReasonManaged.NameSuspiciousPattern] = "Padrão de nome suspeito",
        [BlockReasonManaged.HashNotFound]          = "Hash não encontrado na base de dados",
        [BlockReasonManaged.HashRevoked]           = "Hash revogado",
        [BlockReasonManaged.HashComputeFailure]    = "Falha ao computar hash",
        [BlockReasonManaged.SignatureInvalid]      = "Assinatura inválida",
        [BlockReasonManaged.SignatureAbsent]       = "Assinatura ausente",
        [BlockReasonManaged.SignatureRevoked]      = "Assinatura revogada",
        [BlockReasonManaged.ScoreTooLow]           = "Score abaixo do limiar",
        [BlockReasonManaged.RuleSystemDllOutside]  = "DLL do sistema fora de System32",
        [BlockReasonManaged.RuleTempDirectory]     = "DLL em diretório temporário",
        [BlockReasonManaged.RulePrivilegedProcess] = "Processo privilegiado",
        [BlockReasonManaged.ToctouDetected]        = "Ataque TOCTOU detectado",
        [BlockReasonManaged.UnexpectedModule]      = "Módulo inesperado",
    };

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not BlockReasonManaged flags || flags == BlockReasonManaged.None)
            return Array.Empty<string>();

        return _labels
            .Where(kvp => flags.HasFlag(kvp.Key))
            .Select(kvp => kvp.Value)
            .ToList();
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
