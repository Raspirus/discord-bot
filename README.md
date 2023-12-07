# discord-bot
The Raspirus Discord bot

# Setup for Balena Cloud
1. Create a new Balena Cloud application
2. Add a new device to the application
3. Download the Balena OS image for the device
4. Flash the image to an SD card
5. Insert the SD card into the Raspberry Pi
6. Power on the Raspberry Pi
7. Open the command line and run `balena login`
8. Run `balena push <application name>`
9. Wait for the application to build and deploy
10. The bot should now be running on the Raspberry Pi

Tip: You can find the application name in the Balena Cloud dashboard

Invite link: https://discord.com/api/oauth2/authorize?client_id=1173019507565006869&permissions=8&scope=bot+applications.commands