
import os
import requests

def image_to_text(image_path):
    api_key = 'K87549321588957'  # Replace with your OCR.space API key

    with open(image_path, 'rb') as f:
        image_data = f.read()

    url = 'https://api.ocr.space/parse/image'
    headers = {'apikey': api_key}
    files = {'file': ('image.png', image_data, 'image/png')}
    data = {
        'language': 'chs',  # Chinese Simplified
        'isOverlayRequired': False
    }

    response = requests.post(url, headers=headers, files=files, data=data)
    response.raise_for_status()

    result = response.json()

    if 'ParsedResults' not in result:
        error_message = result.get('ErrorMessage', 'Unknown error')
        error_details = result.get('ErrorDetails', '')
        raise ValueError(f"OCR.space API error: {error_message} ({error_details})")

    chinese_text = result['ParsedResults'][0]['ParsedText']

    return chinese_text

def save_text_to_file(image_path, text):
    base_name = os.path.splitext(os.path.basename(image_path))[0]
    output_file_name = f"{base_name}.txt"
    output_file_path = os.path.join(os.getcwd(), output_file_name)

    with open(output_file_path, 'w', encoding='utf-8') as f:
        f.write(text)

    print(f"Text saved to {output_file_path}")

def main():
    image_path = r'D:\Tools\Chinese-OCR\test.png'
    recognized_text = image_to_text(image_path)
    save_text_to_file(image_path, recognized_text)

if __name__ == "__main__":
    main()
