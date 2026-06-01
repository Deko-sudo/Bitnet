using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using BitNet.Desktop.Native;
using System;
using System.Runtime.InteropServices;
using System.Text;
using Windows.ApplicationModel.DataTransfer;

namespace BitNet.Desktop.Views
{
    public sealed partial class GeneratorPage : Page
    {
        private DispatcherTimer? _clipboardClearTimer;

        public GeneratorPage()
        {
            this.InitializeComponent();
            UpdateStrengthIndicator();
        }

        private void GenerateButton_Click(object sender, RoutedEventArgs e)
        {
            var ptr = BitnetCore.bitnet_generate_password(
                (int)LengthSlider.Value,
                UpperCheck.IsChecked == true ? 1 : 0,
                LowerCheck.IsChecked == true ? 1 : 0,
                DigitsCheck.IsChecked == true ? 1 : 0,
                SymbolsCheck.IsChecked == true ? 1 : 0,
                AmbiguousCheck.IsChecked == true ? 1 : 0);

            if (ptr != IntPtr.Zero)
            {
                try
                {
                    var password = Marshal.PtrToStringUTF8(ptr);
                    ResultBox.Text = password ?? "";
                    UpdateStrengthIndicator();
                }
                finally
                {
                    BitnetCore.bitnet_free_string(ptr);
                }
            }
        }

        private void CopyButton_Click(object sender, RoutedEventArgs e)
        {
            var text = ResultBox.Text;
            if (string.IsNullOrEmpty(text)) return;
            var package = new DataPackage();
            package.SetText(text);
            Clipboard.SetContent(package);
            StartClipboardClearTimer();
        }

        private void LengthSlider_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
        {
            UpdateStrengthIndicator();
        }

        private void UpdateStrengthIndicator()
        {
            var length = (int)LengthSlider.Value;
            var score = CalculateStrength(length);
            StrengthBar.Value = score;

            if (score < 40)
            {
                StrengthBar.Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.OrangeRed);
                StrengthLabel.Text = "Weak";
            }
            else if (score < 70)
            {
                StrengthBar.Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gold);
                StrengthLabel.Text = "Moderate";
            }
            else
            {
                StrengthBar.Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.LimeGreen);
                StrengthLabel.Text = "Strong";
            }
        }

        private int CalculateStrength(int length)
        {
            var score = length * 2;
            if (UpperCheck.IsChecked == true) score += 10;
            if (LowerCheck.IsChecked == true) score += 10;
            if (DigitsCheck.IsChecked == true) score += 10;
            if (SymbolsCheck.IsChecked == true) score += 15;
            if (AmbiguousCheck.IsChecked == true) score += 5;
            return Math.Min(score, 100);
        }

        private void StartClipboardClearTimer()
        {
            _clipboardClearTimer?.Stop();
            _clipboardClearTimer = new DispatcherTimer();
            _clipboardClearTimer.Interval = TimeSpan.FromSeconds(30);
            _clipboardClearTimer.Tick += (s, e) =>
            {
                Clipboard.Clear();
                _clipboardClearTimer?.Stop();
            };
            _clipboardClearTimer.Start();
        }
    }
}