#!/usr/bin/env python3
"""
PDF Extraction Demo

This demo shows PDF table extraction capabilities:
1. Extract tables from PDF files
2. Apply business logic from JSON mapping
3. Handle different PDF formats
4. Security limits on extraction
"""
import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# At the top of each demo
try:
    from dotenv import load_dotenv

    load_dotenv()
    print("✅ Loaded .env configuration")
except ImportError:
    print("⚠️  Install python-dotenv: pip install python-dotenv")

# Check if pdfplumber is available
try:
    import pdfplumber

    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("⚠️  pdfplumber not installed. PDF extraction will be simulated.")
    print("   Install with: pip install pdfplumber")

from etl_framework.core.load_strategy import LoadStrategy

# Import ETL Framework components
from etl_framework.core.pipeline import ETLPipeline
from etl_framework.plugins.extractors.csv_extractor import CSVExtractor
from etl_framework.plugins.extractors.pdf_extractor import PDFExtractor
from etl_framework.plugins.loaders.file_loader import FileLoader
from etl_framework.plugins.transformers.cleaner import DataCleaner
from etl_framework.plugins.transformers.mapping_loader import MappingLoader


def create_sample_pdf():
    """Create a sample PDF file for demonstration."""
    import io

    import pandas as pd
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    demo_dir = Path(__file__).parent
    pdf_file = demo_dir / "data" / "sample_invoice.pdf"

    # Create a simple PDF with tabular data
    c = canvas.Canvas(str(pdf_file), pagesize=letter)
    width, height = letter

    # Add title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, height - 100, "Sample Invoice")

    # Add company info
    c.setFont("Helvetica", 12)
    c.drawString(100, height - 130, "Acme Corporation")
    c.drawString(100, height - 150, "123 Business St, City, State 12345")

    # Add table headers
    headers = ["Item", "Description", "Quantity", "Unit Price", "Total"]
    col_widths = [80, 200, 80, 80, 80]
    x_pos = 100
    y_pos = height - 200

    c.setFont("Helvetica-Bold", 12)
    for i, header in enumerate(headers):
        c.drawString(x_pos, y_pos, header)
        x_pos += col_widths[i]

    # Add table data
    data = [
        ["RD-1001", "Roller Door - Aluminum", "2", "$1,250.00", "$2,500.00"],
        ["RD-1002", "Roller Door - Steel", "1", "$1,800.50", "$1,800.50"],
        ["INST", "Installation", "1", "$500.00", "$500.00"],
        ["SHIP", "Shipping", "1", "$250.00", "$250.00"],
    ]

    y_pos -= 30
    c.setFont("Helvetica", 12)

    for row in data:
        x_pos = 100
        for i, cell in enumerate(row):
            c.drawString(x_pos, y_pos, str(cell))
            x_pos += col_widths[i]
        y_pos -= 25

    # Add total
    y_pos -= 30
    c.setFont("Helvetica-Bold", 12)
    c.drawString(100, y_pos, "Total: $5,050.50")

    c.save()
    print(f"   Created sample PDF: {pdf_file}")
    return pdf_file


def simulate_pdf_extraction():
    """Simulate PDF extraction if pdfplumber is not available."""
    import pandas as pd

    # Create simulated PDF data
    data = {
        "col_1": ["RD-1001", "RD-1002", "INST", "SHIP"],
        "col_2": [
            "Roller Door - Aluminum",
            "Roller Door - Steel",
            "Installation",
            "Shipping",
        ],
        "col_3": ["2", "1", "1", "1"],
        "col_4": ["1250.00", "1800.50", "500.00", "250.00"],
        "col_5": ["2500.00", "1800.50", "500.00", "250.00"],
        "page": [1, 1, 1, 1],
        "table": [1, 1, 1, 1],
    }

    return pd.DataFrame(data)


def main():
    """Run the PDF extraction demo."""
    print("=" * 70)
    print("📄 PDF EXTRACTION DEMO")
    print("=" * 70)
    print("This demo shows PDF table extraction capabilities.")
    print()

    # Setup paths
    demo_dir = Path(__file__).parent
    data_dir = demo_dir / "data"
    output_dir = demo_dir / "output"
    config_dir = demo_dir / "config"

    # Ensure directories exist
    data_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    # Create sample PDF if needed
    pdf_file = data_dir / "sample_invoice.pdf"
    if not pdf_file.exists():
        print("📝 Creating sample PDF file...")
        pdf_file = create_sample_pdf()
    else:
        print(f"📝 Using existing PDF file: {pdf_file}")

    # Define other file paths
    mapping_file = config_dir / "roller_door_mapping.json"
    output_file = output_dir / "extracted_invoice_data.csv"

    print()
    print("📁 File Paths:")
    print(f"   PDF Source:  {pdf_file}")
    print(f"   Mapping:     {mapping_file}")
    print(f"   Output:      {output_file}")
    print()

    # Check if mapping file exists
    if not mapping_file.exists():
        print(f"❌ Error: Mapping file not found: {mapping_file}")
        return 1

    # Create pipeline
    print("🔧 Creating ETL pipeline...")
    pipeline = ETLPipeline(username="operator", enable_security=True)

    # Register extractor based on availability
    if PDF_AVAILABLE:
        print("   Using PDF extractor (pdfplumber available)")
        pipeline.register_extractor("pdf", PDFExtractor())
        extractor_name = "pdf"
    else:
        print("   Using CSV extractor (simulating PDF data)")
        pipeline.register_extractor("csv", CSVExtractor())
        extractor_name = "csv"

        # Create CSV version of PDF data for simulation
        csv_file = data_dir / "simulated_pdf_data.csv"
        if not csv_file.exists():
            df = simulate_pdf_extraction()
            df.to_csv(csv_file, index=False)
            print(f"   Created simulated CSV: {csv_file}")
        pdf_file = csv_file  # Use CSV instead of PDF

    # Add transformers
    print("🔄 Adding transformers...")

    # Custom column mapping for PDF extraction
    pdf_column_mapping = {
        "col_1": "item_code",
        "col_2": "description",
        "col_3": "quantity",
        "col_4": "unit_price",
        "col_5": "total_price",
    }

    pipeline.add_transformer(
        DataCleaner(column_mapping=pdf_column_mapping, enable_security=True)
    )

    # JSON mapping loader (will override some mappings)
    pipeline.add_transformer(MappingLoader(str(mapping_file), enable_security=True))

    # Register loader
    pipeline.register_loader("file", FileLoader())

    # Run the pipeline
    print("🚀 Running PDF extraction pipeline...")
    print(f"   Extractor:   {extractor_name.upper()}")
    print(f"   Transformers: DataCleaner, MappingLoader")
    print(f"   Loader:      File")
    print(f"   Strategy:    REPLACE")
    print()

    try:
        result = pipeline.run(
            extractor_name=extractor_name,
            source=str(pdf_file),
            loader_name="file",
            target=str(output_file),
            strategy=LoadStrategy.REPLACE,
        )

        if result is not None:
            print("✅ PDF extraction completed successfully!")
            print()
            print("📊 Results:")
            print(f"   Rows extracted: {len(result)}")
            print(f"   Columns:        {list(result.columns)}")
            print()

            # Show extracted data
            print("🔍 Extracted data:")
            print(result.to_string())
            print()

            # Show security features
            if PDF_AVAILABLE:
                print("🔒 PDF Extraction Security Features:")
                print("   • Page limit: 100 pages (configurable)")
                print("   • Table limit: 10 tables per page")
                print("   • File size limit: 100MB")
                print("   • Path traversal protection")
                print("   • File type validation")

            print()
            print("💾 Output saved to:")
            print(f"   {output_file}")
            print()

            # Clean shutdown
            pipeline.shutdown()

            return 0
        else:
            print("❌ PDF extraction failed - no result returned")
            pipeline.shutdown()
            return 1

    except Exception as e:
        print(f"❌ Pipeline error: {e}")
        import traceback

        traceback.print_exc()

        # Clean shutdown even on error
        try:
            pipeline.shutdown()
        except:
            pass

        return 1


if __name__ == "__main__":
    # Import pandas here to avoid dependency if not needed
    import pandas as pd

    exit_code = main()

    print("=" * 70)
    if exit_code == 0:
        print("🎉 PDF extraction demo completed successfully!")
    else:
        print("❌ PDF extraction demo failed.")
    print("=" * 70)

    sys.exit(exit_code)
