# streamlit_app.py - ملف وهمي لتشغيل Flask على Streamlit Cloud

import subprocess
import sys

# هذا الملف فقط لتمرير متطلبات Streamlit Cloud
# السيرفر الحقيقي هو smart_api.py

if __name__ == "__main__":
    # تشغيل Flask API
    subprocess.run([sys.executable, "smart_api.py"])