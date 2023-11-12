import os
from dotenv import load_dotenv
import discord
from discord.ext import commands
import hashlib
import aiohttp
import json
import requests
from pretty_help import EmojiMenu, PrettyHelp

menu = EmojiMenu(page_left="⬅️", page_right="➡️", remove="❌", active_time=5)

# Custom ending note
ending_note = "The ending note from {ctx.bot.user.name}\nFor command {help.clean_prefix}{help.invoked_with}"

load_dotenv()

intents = discord.Intents.default()
intents.message_content = True
activity = discord.Activity(type=discord.ActivityType.watching, name="for malware")

bot = commands.Bot(command_prefix='!', intents=intents, activity=activity)
bot.help_command = PrettyHelp(menu=menu, ending_note=ending_note)
bot.description = f"Hello there! I'm Raspirus. My prefix is {bot.command_prefix}"
bot.case_insensitive = True


async def hash_helper_method(ctx, result, md5_hash):
    marked_as_malware_count = 0
    for key in result['virustotal']['scans'].keys():
        if result['virustotal']['scans'][key]['detected']:
            marked_as_malware_count += 1

    with open('result.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=4)

    # Print the response back to the server
    await ctx.reply(f"Hash {md5_hash} has been marked as malware by "
                    f"{marked_as_malware_count} out of {len(result['virustotal']['scans'].keys())} antivirus "
                    f"software\n"
                    f"Extensive report below:",
                    file=discord.File('result.json'))


@bot.command(brief="Scans the attached file for malware")
async def scan(ctx):
    if len(ctx.message.attachments) == 0:
        await ctx.reply("No file attached")
        return
    attachment_url = ctx.message.attachments[0].url
    file = requests.get(attachment_url)

    md5_hash = hashlib.md5(file.content).hexdigest()

    # Send the MD5 hash to the API and wait for the response
    async with aiohttp.ClientSession() as session:
        async with session.get(
                f'https://virusshare.com/apiv2/file?apikey={os.getenv("API_KEY")}&hash={md5_hash}') as response:
            result = await response.json()

    if response.status != 200:
        await ctx.reply("Issue with the API, please try again later")
        return

    try:
        await hash_helper_method(ctx, result, md5_hash)
    except KeyError:
        await ctx.reply("File seems to be safe")


@bot.command(brief="Shows the bots latency")
async def ping(ctx):
    # Get the bots latency (ping) to the server
    latency = bot.latency * 1000  # Convert to milliseconds
    await ctx.reply(f'Ping: {latency:.2f}ms')


@bot.command(brief="Returns the hash of the attached file. Supported algorithms: MD5, SHA256")
async def hash(ctx, method):
    # Read the file and calculate the hash using the specified algorithm
    if len(ctx.message.attachments) == 0:
        await ctx.reply("No file attached")
        return
    attachment_url = ctx.message.attachments[0].url
    file = requests.get(attachment_url)

    if method.lower() == 'md5':
        hash_value = hashlib.md5(file.content).hexdigest()
    elif method.lower() == 'sha256':
        hash_value = hashlib.sha256(file.content).hexdigest()
    else:
        await ctx.reply('Invalid hash algorithm. Supported algorithms: MD5, SHA256')
        return

    await ctx.reply(f'Hash ({method}): {hash_value}')


@bot.command(brief="Checks if the given MD5 hash is in the database")
async def check(ctx, md5_hash):
    # Verify if the given hash is in MD5 format
    if len(md5_hash) != 32:
        await ctx.reply('Invalid MD5 hash format')
        return

    # Send the hash to the API and wait for the response
    async with aiohttp.ClientSession() as session:
        async with session.get(
                f'https://virusshare.com/apiv2/file?apikey={os.getenv("API_KEY")}&hash={md5_hash}') as response:
            result = await response.json()

    if response.status != 200:
        await ctx.reply("Issue with the API, please try again later")
        return

    marked_as_malware_count = 0
    try:
        await hash_helper_method(ctx, result, md5_hash)
    except KeyError:
        await ctx.reply("Hash not found in the database")


@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name} ({bot.user.id})')


bot.run(os.getenv('BOT_TOKEN'))