#/bin/bash

template_file="template.h.tmpl"

for file in $@
do
	base_name=`basename $file .h`
	macro_name=${base_name^^}
	macro_name=${macro_name//-/_}
	
	echo "filename: $file, macro_name: $macro_name"
	sed -e "s/{macro_name}/${macro_name}/g" $template_file > ${base_name}.h

done
