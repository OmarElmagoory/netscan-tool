#!/bin/bash
echo "🔧 بدء تثبيت أداة netscan..."
sudo cp netscan /usr/local/bin/
sudo chmod +x /usr/local/bin/netscan
mkdir -p ~/netscan
echo "✅ تم تثبيت الأداة بنجاح!"
echo "يمكنك الآن تشغيلها بالأمر: sudo netscan"
