import os
from dotenv import load_dotenv
import discord
from discord.ext import commands
import hashlib
import aiohttp
import json
import requests

load_dotenv()

intents = discord.Intents.default()
intents.message_content = True
activity = discord.Activity(type=discord.ActivityType.watching, name="for malware")

bot = commands.Bot(intents=intents, activity=activity)
bot.case_insensitive = True


async def hash_helper_method(ctx, result, md5_hash):
    """
    This is a helper method for the scan and check commands. It takes the response from the API and the MD5 hash and
    prints the result to the server.

    :param ctx: The context of the command
    :param result: The response from the API
    :param md5_hash: The MD5 hash of the file
    :return: None
    """
    marked_as_malware_count = 0
    # Counts the amount of antivirus software that marked the file as malware
    for key in result['virustotal']['scans'].keys():
        if result['virustotal']['scans'][key]['detected']:
            marked_as_malware_count += 1

    # Saves the entire API response in a JSON file for a more in-depth report
    with open('result.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=4)

    # Print the response back to the server
    await ctx.respond(f"Hash {md5_hash} has been marked as malware by "
                      f"{marked_as_malware_count} out of {len(result['virustotal']['scans'].keys())} antivirus "
                      f"software\n"
                      f"Extensive report below:",
                      file=discord.File('result.json'))


@bot.slash_command(name="scan", description="Scans the attached file for malware")
async def scan(ctx: discord.ApplicationContext, file: discord.Option(discord.SlashCommandOptionType.attachment)):
    """
    This bot command scans the attached file for malware. It sends the MD5 hash of the file to the VirusShare API and
    prints the response back to the server.

    :param ctx: The context of the command
    :param file: The attached file
    :return: None
    """
    print(f"User {ctx.author} requested a scan of the attached file")
    file_obj = requests.get(file)
    md5_hash = hashlib.md5(file_obj.content).hexdigest()

    # Send the MD5 hash to the API and wait for the response
    async with aiohttp.ClientSession() as session:
        async with session.get(
                f'https://virusshare.com/apiv2/file?apikey={os.getenv("API_KEY")}&hash={md5_hash}') as response:
            result = await response.json()

    if response.status != 200:
        await ctx.respond("Issue with the API, please try again later")
        return

    try:
        await hash_helper_method(ctx, result, md5_hash)
    except KeyError:
        await ctx.respond("File seems to be safe, MD5 hash: " + md5_hash)
    print("Scan finished")


@bot.slash_command(name="ping", description="Shows the bots latency", guild_ids=[1132753101485514774])
async def ping(ctx: discord.ApplicationContext):
    """
    Simply returns the bots latency to the server

    :param ctx: The context of the command
    :return: None
    """
    print(f"User {ctx.author} requested the bots latency")
    # Get the bots latency (ping) to the server
    latency = bot.latency * 1000  # Convert to milliseconds
    await ctx.respond(f'Pong: {latency:.2f}ms')
    print(f"Latency: {latency:.2f}ms")


@bot.slash_command(name="hash", description="Returns the hash of the attached file. Supported algorithms: MD5, SHA256")
async def hash(ctx: discord.ApplicationContext, method: discord.Option(str, choices=['MD5', 'SHA256']),
               file: discord.Option(discord.SlashCommandOptionType.attachment)):
    """
    Creates a hash of the attached file. The user can choose between MD5 and SHA256

    :param ctx: The context of the command
    :param method: The hash algorithm
    :param file: The attached file
    :return: None
    """
    print(f"User {ctx.author} requested the hash of the attached file")
    file_obj = requests.get(file)

    if method.lower() == 'md5':
        hash_value = hashlib.md5(file_obj.content).hexdigest()
    elif method.lower() == 'sha256':
        hash_value = hashlib.sha256(file_obj.content).hexdigest()
    else:
        await ctx.respond('Invalid hash algorithm. Supported algorithms: MD5, SHA256')
        return

    await ctx.respond(f'Hash ({method}): {hash_value}')
    print(f"Hash ({method}): {hash_value}")


@bot.slash_command(name="check", description="Checks if the given MD5 hash is in the database")
async def check(ctx: discord.ApplicationContext, md5_hash: discord.Option(discord.SlashCommandOptionType.string)):
    """
    Checks if the given MD5 hash is in the VirusShare database (might be replaced by the Raspirus database in the future)

    :param ctx: The context of the command
    :param md5_hash: The MD5 hash
    :return: None
    """
    print(f"User {ctx.author} requested a check of the MD5 hash {md5_hash}")
    # Verify if the given hash is in MD5 format
    if len(md5_hash) != 32:
        await ctx.respond('Invalid MD5 hash format')
        return

    # Send the hash to the API and wait for the response
    async with aiohttp.ClientSession() as session:
        async with session.get(
                f'https://virusshare.com/apiv2/file?apikey={os.getenv("API_KEY")}&hash={md5_hash}') as response:
            result = await response.json()

    if response.status != 200:
        await ctx.respond("Issue with the API, please try again later")
        return

    try:
        await hash_helper_method(ctx, result, md5_hash)
    except KeyError:
        await ctx.respond("Hash not found in the database")
    print("Scan finished")


@bot.event
async def on_ready():
    """
    Prints the bots name and ID when it is ready

    :return: None
    """
    print(f'Logged in as {bot.user.name} ({bot.user.id})')


bot.run(os.getenv('BOT_TOKEN'))
