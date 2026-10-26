import os
import xml.etree.ElementTree as ET

INPUT_DIR = os.path.join(os.path.dirname(__file__), "../input")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../output")

def analyze_factory():
    print("Starting OutSystems Factory XML analysis...")
    
    if not os.path.exists(INPUT_DIR):
        print(f"Directory '{INPUT_DIR}' not found. Please create it and add your XML files.")
        return

    xml_files = [f for f in os.listdir(INPUT_DIR) if f.endswith('.xml')]
    
    if not xml_files:
        print(f"No XML files found in '{INPUT_DIR}'. Add files to analyze.")
        return

    print(f"Found {len(xml_files)} module XML(s) to process.")
    
    for filename in xml_files:
        filepath = os.path.join(INPUT_DIR, filename)
        print(f"Parsing module: {filename}")
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            # Metadata extraction logic goes here (Entities, Actions, References, etc.)
        except Exception as e:
            print(f"Error parsing {filename}: {e}")

if __name__ == "__main__":
    analyze_factory()