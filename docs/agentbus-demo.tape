Output docs/assets/agentbus-demo.mp4

Set Shell "bash"
Set FontSize 19
Set Width 1200
Set Height 720
Set TypingSpeed 25ms
Set PlaybackSpeed 1
Set Framerate 24
Set MarginFill "#11111b"
Set Margin 24

Hide
Type "make build >/dev/null && ./scripts/demo-daemon.sh reset"
Enter
Sleep 1s
Type "clear"
Enter
Show

Type "./bin/agentbus send --from reviewer --to implementer --allow-new --client-message-id demo-1 --body 'Please review the current diff.' | jq '{message_id, from, to, body}'"
Enter
Sleep 2s

Type "./bin/agentbus wait --name implementer | tee /tmp/agentbus-delivery.json | jq '{delivery_id, redelivery, messages}'"
Enter
Sleep 2s

Type "./scripts/demo-daemon.sh restart  # restart before acknowledgement"
Enter
Sleep 2s

Type "./bin/agentbus wait --name implementer | jq '{delivery_id, redelivery, messages}'"
Enter
Sleep 2s

Type "./bin/agentbus ack --name implementer --delivery-id $(jq -r .delivery_id /tmp/agentbus-delivery.json) | jq"
Enter
Sleep 2s

Type "curl -sS -o /dev/null -w 'mailbox after ack: HTTP %{http_code}' 'http://127.0.0.1:7777/wait?name=implementer&timeout=0.1'; echo"
Enter
Sleep 3s

Hide
Type "./scripts/demo-daemon.sh stop"
Enter
