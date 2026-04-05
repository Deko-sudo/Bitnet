# -*- coding: utf-8 -*-
"""
QR Code Generator для TOTP 2FA

Генерация QR-кодов для настройки 2FA в приложениях аутентификации:
- Google Authenticator
- Authy
- Microsoft Authenticator
- 1Password

Author: Nikita (BE1)
Version: 1.0.0
"""

import io
import base64
from typing import Optional, Tuple, Union
from pathlib import Path

try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    ERROR_CORRECT_L = None
    ERROR_CORRECT_M = None
    ERROR_CORRECT_Q = None
    ERROR_CORRECT_H = None

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# =============================================================================
# Exceptions
# =============================================================================

class QRCodeError(Exception):
    """Базовое исключение для ошибок QR-кода."""
    pass


class QRCodeNotAvailableError(QRCodeError):
    """Библиотека qrcode не доступна."""
    pass


class QRCodeGenerationError(QRCodeError):
    """Ошибка генерации QR-кода."""
    pass


# =============================================================================
# QRCodeGenerator Class
# =============================================================================

class QRCodeGenerator:
    """
    Генератор QR-кодов для TOTP 2FA.
    
    Поддерживаемые форматы вывода:
    - PNG (bytes, base64, файл)
    - SVG
    - ASCII (для терминала)
    
    Пример использования:
        >>> qr = QRCodeGenerator()
        >>> # Генерация QR-кода для TOTP
        >>> uri = "otpauth://totp/MyApp:user@example.com?secret=ABC123&issuer=MyApp"
        >>> png_data = qr.generate(uri)
        >>> # Или с логотипом
        >>> png_data = qr.generate_with_logo(uri, "logo.png")
    """
    
    # Уровни коррекции ошибок
    ERROR_CORRECT_L = ERROR_CORRECT_L  # 7%
    ERROR_CORRECT_M = ERROR_CORRECT_M  # 15%
    ERROR_CORRECT_Q = ERROR_CORRECT_Q  # 25%
    ERROR_CORRECT_H = ERROR_CORRECT_H  # 30%
    
    def __init__(
        self,
        version: int = 1,
        error_correction: int = ERROR_CORRECT_M,
        box_size: int = 10,
        border: int = 4,
    ):
        """
        Инициализация генератора QR-кодов.
        
        Args:
            version: Версия QR-кода (1-40, 1 = автоматический выбор)
            error_correction: Уровень коррекции ошибок
                - ERROR_CORRECT_L: 7% (максимальная плотность)
                - ERROR_CORRECT_M: 15% (по умолчанию)
                - ERROR_CORRECT_Q: 25% (рекомендуется для логотипов)
                - ERROR_CORRECT_H: 30% (максимальная защита)
            box_size: Размер одного "пикселя" в точках
            border: Толщина рамки в блоках
        
        Raises:
            QRCodeNotAvailableError: Если библиотека qrcode не установлена
        
        Example:
            >>> qr = QRCodeGenerator(
            ...     error_correction=QRCodeGenerator.ERROR_CORRECT_Q,
            ...     box_size=12
            ... )
        """
        if not QR_AVAILABLE:
            raise QRCodeNotAvailableError(
                "Библиотека qrcode не установлена. "
                "Установите: pip install qrcode>=7.4"
            )
        
        self._version = version
        self._error_correction = error_correction
        self._box_size = box_size
        self._border = border
        
        # Кэш для повторяющихся URI
        self._cache: dict[str, bytes] = {}
    
    def generate(
        self,
        data: str,
        output_format: str = "png",
        use_cache: bool = False,
    ) -> Union[bytes, str]:
        """
        Генерация QR-кода.
        
        Args:
            data: Данные для кодирования (например, otpauth:// URI)
            output_format: Формат вывода
                - "png": PNG bytes
                - "base64": Base64-encoded PNG
                - "svg": SVG строка
                - "ascii": ASCII art для терминала
            use_cache: Использовать кэширование
        
        Returns:
            QR-код в указанном формате
        
        Raises:
            QRCodeGenerationError: Если не удалось сгенерировать QR-код
        
        Example:
            >>> uri = "otpauth://totp/MyApp:user@example.com?secret=ABC123"
            >>> png_bytes = qr.generate(uri, output_format="png")
            >>> # Или base64 для вставки в HTML
            >>> base64_str = qr.generate(uri, output_format="base64")
        """
        # Проверка кэша
        cache_key = f"{data}:{output_format}"
        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]
        
        try:
            # Создание QR-кода
            qr = qrcode.QRCode(
                version=self._version,
                error_correction=self._error_correction,
                box_size=self._box_size,
                border=self._border,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            # Генерация в зависимости от формата
            if output_format == "png":
                result = self._generate_png(qr)
            elif output_format == "base64":
                result = self._generate_base64(qr)
            elif output_format == "svg":
                result = self._generate_svg(qr)
            elif output_format == "ascii":
                result = self._generate_ascii(qr)
            else:
                raise ValueError(f"Неизвестный формат: {output_format}")
            
            # Кэширование
            if use_cache:
                self._cache[cache_key] = result
            
            return result
        
        except Exception as e:
            raise QRCodeGenerationError(f"Ошибка генерации QR-кода: {e}")
    
    def generate_with_logo(
        self,
        data: str,
        logo_path: Union[str, Path],
        logo_size_ratio: float = 0.2,
        output_format: str = "png",
    ) -> Union[bytes, str]:
        """
        Генерация QR-кода с логотипом в центре.
        
        Args:
            data: Данные для кодирования
            logo_path: Путь к файлу логотипа
            logo_size_ratio: Отношение размера логотипа к размеру QR-кода (0.1-0.3)
            output_format: Формат вывода
        
        Returns:
            QR-код с логотипом в указанном формате
        
        Raises:
            QRCodeGenerationError: Если не удалось сгенерировать QR-код
            FileNotFoundError: Если файл логотипа не найден
        
        Example:
            >>> uri = "otpauth://totp/MyApp:user@example.com?secret=ABC123"
            >>> png_bytes = qr.generate_with_logo(uri, "company_logo.png")
        """
        if not PIL_AVAILABLE:
            raise QRCodeGenerationError(
                "Библиотека Pillow не установлена. "
                "Установите: pip install Pillow>=10.0.0"
            )
        
        logo_path = Path(logo_path)
        if not logo_path.exists():
            raise FileNotFoundError(f"Логотип не найден: {logo_path}")
        
        try:
            # Создание QR-кода с повышенной коррекцией ошибок
            qr = qrcode.QRCode(
                version=self._version,
                error_correction=ERROR_CORRECT_H,  # Максимальная защита для логотипа
                box_size=self._box_size,
                border=self._border,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            # Генерация изображения
            img = qr.make_image(fill_color="black", back_color="white")
            img = img.convert("RGBA")
            
            # Открытие логотипа
            logo = Image.open(logo_path)
            logo = logo.convert("RGBA")
            
            # Расчёт размера логотипа
            qr_width, qr_height = img.size
            logo_size = int(min(qr_width, qr_height) * logo_size_ratio)
            logo = logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
            
            # Позиционирование логотипа по центру
            logo_x = (qr_width - logo_size) // 2
            logo_y = (qr_height - logo_size) // 2
            
            # Наложение логотипа
            img.paste(logo, (logo_x, logo_y), logo)
            
            # Сохранение в зависимости от формата
            buffer = io.BytesIO()
            
            if output_format == "png":
                img.save(buffer, format="PNG", optimize=True)
                return buffer.getvalue()
            elif output_format == "base64":
                img.save(buffer, format="PNG", optimize=True)
                return base64.b64encode(buffer.getvalue()).decode('ascii')
            else:
                raise ValueError(f"Формат '{output_format}' не поддерживается с логотипом")
        
        except Exception as e:
            raise QRCodeGenerationError(f"Ошибка генерации QR-кода с логотипом: {e}")
    
    def generate_totp_qr(
        self,
        username: str,
        secret: str,
        issuer: str,
        algorithm: str = "SHA1",
        digits: int = 6,
        period: int = 30,
        **kwargs,
    ) -> Union[bytes, str]:
        """
        Генерация QR-кода для TOTP 2FA.
        
        Args:
            username: Имя пользователя (email)
            secret: Base32-encoded секрет
            issuer: Название сервиса (например, "Password Manager")
            algorithm: Алгоритм хеширования (SHA1, SHA256, SHA512)
            digits: Количество цифр в коде (6 или 8)
            period: Период обновления кода в секундах
            **kwargs: Дополнительные параметры для generate()
        
        Returns:
            QR-код в указанном формате
        
        Example:
            >>> png_bytes = qr.generate_totp_qr(
            ...     username="user@example.com",
            ...     secret="ABC123DEF456",
            ...     issuer="My Password Manager"
            ... )
        """
        # Формирование otpauth:// URI
        params = {
            'secret': secret,
            'issuer': issuer,
            'algorithm': algorithm.upper(),
            'digits': str(digits),
            'period': str(period),
        }
        
        # URL encoding
        import urllib.parse
        query = urllib.parse.urlencode(params)
        uri = f"otpauth://totp/{issuer}:{username}?{query}"
        
        return self.generate(uri, **kwargs)
    
    def save_to_file(
        self,
        data: str,
        filepath: Union[str, Path],
        **kwargs,
    ) -> Path:
        """
        Сохранение QR-кода в файл.
        
        Args:
            data: Данные для кодирования
            filepath: Путь для сохранения
            **kwargs: Дополнительные параметры для generate()
        
        Returns:
            Путь к сохранённому файлу
        
        Example:
            >>> qr.save_to_file(uri, "qrcode.png")
        """
        filepath = Path(filepath)
        
        # Определение формата по расширению
        format_map = {
            '.png': 'png',
            '.svg': 'svg',
            '.txt': 'ascii',
        }
        
        output_format = kwargs.pop('output_format', None)
        if output_format is None:
            output_format = format_map.get(filepath.suffix.lower(), 'png')
        
        # Генерация
        qr_data = self.generate(data, output_format=output_format, **kwargs)
        
        # Сохранение
        if output_format in ('png',):
            filepath.write_bytes(qr_data)
        else:
            filepath.write_text(qr_data, encoding='utf-8')
        
        return filepath
    
    def _generate_png(self, qr: qrcode.QRCode) -> bytes:
        """Генерация PNG bytes."""
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG", optimize=True)
        return buffer.getvalue()
    
    def _generate_base64(self, qr: qrcode.QRCode) -> str:
        """Генерация Base64-encoded PNG."""
        png_bytes = self._generate_png(qr)
        return base64.b64encode(png_bytes).decode('ascii')
    
    def _generate_svg(self, qr: qrcode.QRCode) -> str:
        """Генерация SVG строки."""
        # Ручная генерация SVG
        matrix = qr.get_matrix()
        box_size = self._box_size
        border = self._border
        
        # Расчёт размеров
        width = (len(matrix) * box_size) + (border * 2 * box_size)
        height = width
        
        # Генерация SVG
        svg_parts = [
            f'<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
            f'<rect width="{width}" height="{height}" fill="white"/>',
        ]
        
        # Добавление чёрных квадратов
        for y, row in enumerate(matrix):
            for x, cell in enumerate(row):
                if cell:
                    svg_parts.append(
                        f'<rect x="{(x + border) * box_size}" y="{(y + border) * box_size}" '
                        f'width="{box_size}" height="{box_size}" fill="black"/>'
                    )
        
        svg_parts.append('</svg>')
        return '\n'.join(svg_parts)
    
    def _generate_ascii(self, qr: qrcode.QRCode) -> str:
        """Генерация ASCII art для терминала."""
        # Символы для ASCII representation
        full_block = '██'
        empty_block = '  '
        
        # Получение матрицы QR-кода
        matrix = qr.get_matrix()
        
        # Генерация ASCII
        lines = []
        for row in matrix:
            line = ''.join(full_block if cell else empty_block for cell in row)
            lines.append(line)
        
        return '\n'.join(lines)
    
    def clear_cache(self) -> None:
        """Очистка кэша."""
        self._cache.clear()
    
    def get_stats(self) -> dict:
        """
        Получить статистику использования.
        
        Returns:
            Словарь со статистикой
        """
        return {
            'cached_items': len(self._cache),
            'qr_available': QR_AVAILABLE,
            'pil_available': PIL_AVAILABLE,
        }


# =============================================================================
# Convenience Functions
# =============================================================================

def generate_totp_qr(
    username: str,
    secret: str,
    issuer: str,
    output_format: str = "base64",
) -> Union[bytes, str]:
    """
    Быстрая генерация TOTP QR-кода.
    
    Args:
        username: Имя пользователя (email)
        secret: Base32-encoded секрет
        issuer: Название сервиса
        output_format: Формат вывода ("base64" или "png")
    
    Returns:
        QR-код в указанном формате
    
    Example:
        >>> qr_base64 = generate_totp_qr(
        ...     username="user@example.com",
        ...     secret="ABC123DEF456",
        ...     issuer="MyApp"
        ... )
        >>> # Для HTML: <img src="data:image/png;base64,{qr_base64}" />
    """
    qr = QRCodeGenerator(error_correction=QRCodeGenerator.ERROR_CORRECT_Q)
    return qr.generate_totp_qr(
        username=username,
        secret=secret,
        issuer=issuer,
        output_format=output_format,
    )


def generate_qr_file(
    data: str,
    filepath: Union[str, Path],
    **kwargs,
) -> Path:
    """
    Быстрое сохранение QR-кода в файл.
    
    Args:
        data: Данные для кодирования
        filepath: Путь для сохранения
        **kwargs: Дополнительные параметры
    
    Returns:
        Путь к сохранённому файлу
    
    Example:
        >>> generate_qr_file("https://example.com", "qrcode.png")
    """
    qr = QRCodeGenerator()
    return qr.save_to_file(data, filepath, **kwargs)


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Exceptions
    'QRCodeError',
    'QRCodeNotAvailableError',
    'QRCodeGenerationError',
    
    # Main class
    'QRCodeGenerator',
    
    # Convenience functions
    'generate_totp_qr',
    'generate_qr_file',
    
    # Feature flags
    'QR_AVAILABLE',
    'PIL_AVAILABLE',
]
