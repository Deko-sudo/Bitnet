using System;
using System.Windows;

namespace BitNet.TestWindow;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Console.WriteLine("[WPF Test] MainWindow constructor OK");
    }

    private void Button_Click(object sender, RoutedEventArgs e)
    {
        StatusText.Text = "Button clicked at " + DateTime.Now.ToLongTimeString();
    }
}
