#this script saves all issues into json files

offset=0
domain='https://pandg.nonamesec.com'
bearertoken='eyXXXXX.eyXXX.DOH'
maxissues=5000

while [ $offset -le $maxissues ] 
outfile='out'"$offset"'.json' 
do
 curl -vX 'GET' \
  ''"$domain"'/api/v3/issues?returnFields=id&returnFields=api&returnFields=title&returnFields=module&returnFields=severity&returnFields=status&returnFields=owaspTag&returnFields=detectionTime&returnFields=triggeredOn&returnFields=description&returnFields=countries&returnFields=ips&returnFields=impact&returnFields=remediation&returnFields=investigate&returnFields=responseCodes&returnFields=attacker&returnFields=comments&returnFields=tickets&returnFields=evidence&sortDesc=true&limit=100&offset='"$offset"'&detectionStartDate=2023-03-08T16%3A54%3A27.535Z&detectionEndDate=2023-09-12T16%3A54%3A27.535Z&status=Open&status=In%20Progress&status=Rejected%20%28IP%20in%20AllowList%29&status=Rejected%20%28User%20on%20AllowList%29&status=Rejected%20%28User%20Agents%20on%20AllowList%29&status=Rejected%20%28Ignored%29&status=Rejected%20%28Not%20a%20Problem%29&status=Resolve%20%28Remediated%29&status=Resolve%20%28Blocked%29&status=Resolve&status=False%20Positive&status=Reoccurring&status=False%20Positive%20Resolved&severity=Critical&severity=High&severity=Medium&severity=Low&severity=Info' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer '"$bearertoken"'' \
  -o $outfile''
  offset=$(($offset+100))

done
