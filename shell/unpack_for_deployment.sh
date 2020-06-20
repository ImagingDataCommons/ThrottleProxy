echo "Unpacking JSON and txt files for deployment..."
cp ./txt/* ./
cp ./json/* ./

echo "JSON and txt files unpacked:"
ls ./*.txt
ls ./*.json

# File test for requirements.txt...
if [ ! -f "requirements.txt" ]; then
    echo "[ERROR] requirements.txt is missing! Something went wrong in text packing/unpacking."
    exit 1
fi
