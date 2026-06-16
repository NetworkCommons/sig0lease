dia_dir="./diagrams"
out_dir="${dia_dir}/output"

if [ -d "${out_dir}" ]; then
  echo "Cleaning up existing output directory..."
  rm -f "${out_dir:?}"/*.md "${out_dir:?}"/*.svg
else
  echo "Creating output directory..."
  mkdir -p "${out_dir}"
fi


for i in ${dia_dir}/*.md;
do
    echo "Processing $i"
  filename=$(basename "$i" .md)
  # ./node_modules/.bin/mmdc -i "$i" -o "${out_dir}/${filename}.pdf"
  if ! ./node_modules/.bin/mmdc -i "$i" -o "${out_dir}/${filename}.md"
  then
    echo "Error processing $i"
  fi
done
