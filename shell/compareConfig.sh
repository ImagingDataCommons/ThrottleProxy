#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
    echo "Must specify file to compare"
    exit
fi

CONFIG_PATH=$1

TMP_VERS=$(mktemp /tmp/vers.XXXXXXXXX)
TMP_SORT=$(mktemp /tmp/sort.XXXXXXXXX)
TMP_CURR=$(mktemp /tmp/curr.XXXXXXXXX)
TMP_LAST=$(mktemp /tmp/last.XXXXXXXXX)

cat < /dev/null > ${TMP_VERS}
VERS=`gsutil ls -a ${CONFIG_PATH}`
for VER in ${VERS}; do
  GEN=`echo ${VER} | sed s/.*#//`
  echo ${GEN} >> ${TMP_VERS}
done

VER_LEN=`cat ${TMP_VERS} | wc -l`

if (( ${VER_LEN} < 2 )); then
  echo "No diff: first version for " ${CONFIG_PATH}
  rm -f ${TMP_VERS} ${TMP_SORT} ${TMP_CURR} ${TMP_LAST}
  exit
fi

cat ${TMP_VERS} | sort -n > ${TMP_SORT}
CURR=`tail -n 1 ${TMP_SORT}`
PENULT=`tail -n 2 ${TMP_SORT} | head -n 1`


gsutil cp ${CONFIG_PATH}"#"${PENULT} ${TMP_LAST} > /dev/null 2>&1
gsutil cp ${CONFIG_PATH}"#"${CURR} ${TMP_CURR}  > /dev/null 2>&1

echo "Diff of last to current for" ${CONFIG_PATH} ":"
diff ${TMP_LAST} ${TMP_CURR}

trap 'rm -f ${TMP_VERS} ${TMP_SORT} ${TMP_CURR} ${TMP_LAST}' EXIT

