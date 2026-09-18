import os
import shutil

src = r"C:\Users\wwwpr\.gemini\antigravity\brain\d6348fb3-9adf-4ddd-941d-a80d811ecf3d\choco_decent_mascot_1789627625626.jpg"
dst_dir = r"c:\Users\wwwpr\OneDrive\ドキュメント\network monitoring tool\SOC analysis with AI\static"
os.makedirs(dst_dir, exist_ok=True)
dst = os.path.join(dst_dir, "choco.jpg")

shutil.copy(src, dst)
print("Choco image copied to:", dst)
