namespace BitNet.Wpf;

public partial class App : System.Windows.Application
{
    public App()
    {
        System.Windows.Media.RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
    }
}
