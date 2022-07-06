lint:
	golangci-lint --config .golangci.yml run

# example: make new_message msg=Notification file_name=notification.go
new_message:
	sed "s/{Prefix}/${msg}/g" template > protocol/${file_name}
