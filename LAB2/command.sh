while true
do	
echo  "<html>" > web.html
echo "<h1>" >> web.html
iptables -L FORWARD -n -v -x | awk '$1  ~ /^[0-9]+$/ { printf "IP %s, %d bytes\n" , $8 , $ 2} ' |  grep -v 0.0.0.0/0 >> web.html
echo "<h1>" >> web.html
echo "<form action="block" method="post">" >> web.html
echo "block: <input type="text" name="block" />" >> web.html
echo	                "</br>" >> web.html
echo	                "<button>Block</button>" >> web.html
echo	           " </form>" >> web.html
echo	       " </html>" >> web.html
sleep 2
done

