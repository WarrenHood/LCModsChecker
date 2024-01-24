from __future__ import annotations
import argparse
from dataclasses import dataclass
import re
from typing import Optional
import yaml
import os
import sys
import logging
import asyncio
import aiohttp
from pathlib import Path
import vt
import time
import hashlib
import datetime
import traceback

GITHUB_RE = re.compile(r'\bhttps://github\.com/[^\'"]+\b', re.IGNORECASE)
GITHUB_BLACKLISTED_URLS = ["https://github.com/thunderstore-io/Thunderstore"]
VT_OKAY_CATEGORIES = ["undetected", "harmless", "type-unsupported"]
VT_SCAN_FRESH_DAYS = 30  # Time since last scan before a new vt upload is required


@dataclass
class EngineDetection:
    engine: str
    detection: str
    category: str

    def __repr__(self) -> str:
        return f"{self.engine} ({self.detection})"

    def is_okay(self) -> bool:
        okay = True

        # Ensure that the category is in one of the OKAY categories
        okay = okay and self.category in VT_OKAY_CATEGORIES

        return okay


@dataclass
class AVScanSummary:
    category: str
    detections: list[EngineDetection]

    @staticmethod
    def from_results(results: dict) -> list[AVScanSummary]:
        categories = {}
        for engine, result in results.items():
            category = result.get("category", "UNKNOWN CATEGORY")
            engine_result = EngineDetection(
                engine=engine,
                detection=result.get("result", "UNKNOWN RESULT"),
                category=category,
            )
            categories.setdefault(category, []).append(engine_result)
        output = []
        for category, engine_detections in categories.items():
            output.append(
                AVScanSummary(category=category, detections=engine_detections)
            )
        return output

    def filtered(self) -> AVScanSummary:
        """
        Returns a copy of the `AVScanSummary` with okay detections filtered out
        """
        return AVScanSummary(
            category=self.category,
            detections=[d for d in self.detections if not d.is_okay()],
        )

    def is_okay(self) -> bool:
        """
        Returns `True` if there are no detections for this category
        """
        return len(self.detections) == 0

    def __repr__(self) -> str:
        return f"Detected as {self.category.upper()} by {len(self.detections)} engines:\n  - {{}}\n-------------------------------".format(
            "\n  - ".join(map(str, self.detections))
        )


@dataclass
class AVScanSummaries:
    summaries: list[AVScanSummary]

    @staticmethod
    def from_results(results: dict) -> AVScanSummaries:
        return AVScanSummaries(summaries=AVScanSummary.from_results(results))

    def filtered(self):
        return AVScanSummaries(summaries=[s.filtered() for s in self.summaries])

    def is_ok(self):
        """
        Returns whether or not the scanned file has any detections
        """
        for summary in self.summaries:
            if not summary.is_okay():
                return False
        return True

    def __repr__(self) -> str:
        return "\n".join(
            map(
                str,
                (
                    s
                    for s in sorted(self.summaries, key=lambda s: s.category)
                    if not s.is_okay()
                ),
            )
        )


@dataclass
class LCMod:
    name: str
    author: str
    url: str
    dlls: list[str]
    source_url: Optional[str]

    def __repr__(self) -> str:
        return f"\nMod: {self.name} by {self.author}\nMod page: {self.url}\nGithub repo:{self.source_url}\nDLLs:\n  {{}}".format(
            "\n  ".join(self.dlls)
        )

    async def get_mock_dll_anal(self, vt_client: vt.Client, dll: str) -> dict:
        """
        Returns fake analysis of a given DLL
        """
        stats = {}
        results = {
            "MockAV 1": {"category": "malicious", "result": "MockResult-Malicious"},
            "MockAV 2": {"category": "harmless", "result": "MockResult-Harmless"},
            "MockAV 3": {"category": "suspicious", "result": "MockResult-Sussy"},
            "MockAV 4": {"category": "suspicious", "result": "MockResult-SussyBaka"},
        }
        return {
            "attributes": {
                "stats": stats,
                "results": results,
            }
        }

    async def get_dll_anal(self, vt_client: vt.Client, dll: str) -> dict:
        """
        Attempts to get the latest analysis of a given DLL based on md5 hash, otherwise uploads the file to VirusTotal.
        """
        with open(dll, "rb") as f:
            md5 = hashlib.md5(f.read()).hexdigest()

        anal = None
        try:
            vt_file = await vt_client.get_object_async(f"/files/{md5}")
        except vt.error.APIError as e:
            logging.error(f"Got an API Error while getting anal: {e}")
            vt_file = {}
        last_anal_results = vt_file.get("last_analysis_results")
        last_anal_stats = vt_file.get("last_analysis_stats")
        if last_anal_results is not None and last_anal_stats is not None:
            last_scan_date = datetime.datetime.utcfromtimestamp(
                vt_file.get("last_analysis_date", 0)
            )
            days_since_last_scan = (datetime.datetime.utcnow() - last_scan_date).days
            if days_since_last_scan <= VT_SCAN_FRESH_DAYS:
                logging.debug(
                    f"It has been {days_since_last_scan} days since the last scan. Reusing last analysis..."
                )
                anal = {
                    "attributes": {
                        "stats": last_anal_stats,
                        "results": last_anal_results,
                    }
                }
            else:
                logging.warning(
                    f"It has been {days_since_last_scan} days since the last scan. Reuploading..."
                )
        else:
            logging.info(
                "File hasn't ever been scanned before. Uploading to VirusTotal for scan..."
            )
        if anal is None:
            with open(dll, "rb") as f:
                anal = (
                    await vt_client.scan_file_async(f, wait_for_completion=True)
                ).to_dict()
        return anal

    async def av_scan(self, vt_client: vt.Client, delay=15.0) -> None:
        """
        Gets a VirusTotal analysis of the dll, and prints the results
        """
        for dll in self.dlls:
            last_scan_time = datetime.datetime.now()
            try:
                if not os.path.exists(dll):
                    logging.error(
                        f"[{self.name}] DLL {dll} appears to be missing. Unable to run AV scan on it."
                    )
                    continue
                logging.info(f"Running AV scan on {dll}")
                with open(dll, "rb") as f:
                    anal = await self.get_dll_anal(vt_client, dll)
                    # anal = await self.get_mock_dll_anal(vt_client, dll)
                    self.print_anal(dll, anal)
                logging.debug(f"Waiting for {delay} seconds")
            except Exception:
                logging.error(f"Failed to scan {dll}:\n{traceback.format_exc()}")
            seconds_since_last_scan = (datetime.datetime.now() - last_scan_time).seconds
            if seconds_since_last_scan < delay:
                # Ensure we don't go faster than 1 scan every 15 seconds (4 scans per minute)
                await asyncio.sleep(delay - seconds_since_last_scan)

    def print_anal(self, dll: str, stats: dict) -> None:
        logging.debug(f"VirusTotal analysis for DLL: {dll}")
        logging.debug(str(stats))
        results = stats.get("attributes", {}).get("results", {})
        av_result = AVScanSummaries.from_results(results).filtered()
        if not av_result.is_ok():
            print(f"Unsafe dll detected: {dll}")
            print(av_result)


def get_mods(mods_file: str) -> list[LCMod]:
    with open(mods_file, "r") as f:
        mods_yaml: list[dict] = yaml.safe_load(f.read())
    mods = []
    profile_dir = os.path.dirname(mods_file)
    exclusions = get_scan_exclusions()
    for mod in mods_yaml:
        mod_name = mod.get("name")
        mod_author = mod.get("authorName")
        mod_url = mod.get("websiteUrl")
        if mod_name is None or mod_author is None or mod_url is None:
            logging.warning(
                f"Mod {mod_name} is missing either a mod name, author or url. Skipping checks on it..."
            )
            continue
        if mod_name in exclusions:
            logging.debug(f"Skipping mod {mod_name} - present in scan_exclusions.txt")
            continue
        mod_dlls = get_mod_dlls(profile_dir, mod_name)
        if len(mod_dlls) > 0:
            mod = LCMod(
                name=mod_name,
                author=mod_author,
                url=mod_url,
                source_url=None,
                dlls=mod_dlls,
            )
            logging.info(f"Detected {len(mod_dlls)} DLLs in mod {mod.name}")
            mods.append(mod)
    return mods


async def gather_tasks_in_batches(
    tasks: list[asyncio.Task], delay: float = 1.0, batch_size: int = 5
) -> list:
    results = []
    for i in range(0, len(tasks), batch_size):
        results += await asyncio.gather(*tasks[i : i + batch_size])
        logging.info(
            f"Progress: {float(min(i+batch_size, len(tasks)))/float(len(tasks))*100.0:<.2f}% ({min(i+batch_size, len(tasks))}/{len(tasks)})"
        )
        await asyncio.sleep(delay)
    return results


async def populate_mod_url(mod: LCMod, session: aiohttp.ClientSession) -> LCMod:
    """
    Given an LCMod, returns an LCMod with a populated url (if valid and reachable)
    """
    try:
        for i in range(10):
            async with session.get(mod.url) as mod_page_response:
                if mod_page_response.status == 429:
                    logging.debug(
                        f"Got status 429 for mod page: {mod.url}. Retrying in 1 second..."
                    )
                    await asyncio.sleep(1.0)
                    continue
                if mod_page_response.status != 200:
                    raise Exception(
                        f"Got non-zero status code: {mod_page_response.status}"
                    )
                github_source_urls: list[str] = GITHUB_RE.findall(
                    (await mod_page_response.content.read()).decode()
                )
                for url in github_source_urls:
                    is_blacklisted = False
                    for blacklisted in GITHUB_BLACKLISTED_URLS:
                        if url.lower().strip() == blacklisted.lower().strip():
                            is_blacklisted = True
                            break
                        if is_blacklisted:
                            continue
                        # TODO: Validate this url
                        return LCMod(
                            name=mod.name,
                            author=mod.author,
                            url=mod.url,
                            dlls=mod.dlls,
                            source_url=url,
                        )
    except Exception as e:
        logging.exception(f"Error while checking mod {mod}")
    return mod


def get_mod_dlls(profile_dir: str, mod_name: str) -> list[str]:
    """
    Given an r2modman profile path, and a mod name, returns whether the mod has DLLs
    """
    mod_dir = os.path.join(profile_dir, "BepInEx", "plugins", mod_name)
    if not os.path.exists(mod_dir):
        raise Exception(
            f"Mod {mod_name} is missing from your r2modman profile. Please ensure it is installed"
        )
    return list(map(str, Path(mod_dir).glob("**/*.dll")))


async def populate_mod_urls(mods: list[LCMod]) -> list[LCMod]:
    """
    Given a list of `LCMods`, returns a new list of `LCMods` with populated `source_url` (if valid and reachable)
    """
    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.ensure_future(populate_mod_url(mod, session)) for mod in mods]
        return await gather_tasks_in_batches(tasks)


def get_scan_exclusions():
    exclusions_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "scan_exclusions.txt"
    )
    logging.debug(f"Loading mod scan exclusions from {exclusions_file}")
    if not os.path.exists(exclusions_file):
        with open(exclusions_file, "w") as f:
            logging.info(f"Creating default scan exclusions file at {exclusions_file}")
            f.write(
                "# Enter the name of each mod to exclude from scanning on their own lines below\nBepInEx-BepInExPack\n"
            )
    if not os.path.exists(exclusions_file):
        logging.warning(f"Scan exclusions file missing at {exclusions_file}")
        return ["BepInEx-BepInExPack"]
    exclusions = []
    with open(exclusions_file, "r") as f:
        for ln in f:
            exclusion = ln.strip()
            if exclusion.startswith("#") or len(exclusion) == 0:
                continue
            logging.debug(f"Found exclusion '{exclusion}'")
            exclusions.append(exclusion)
    return exclusions


async def main():
    parser = argparse.ArgumentParser(
        description="A script that automatically reviews a given Lethal Company modlist"
    )
    parser.add_argument("modlist", type=str)
    parser.add_argument(
        "-d",
        "--debug",
        help="Enable debug logging",
        action="store_const",
        dest="log_level",
        const=logging.DEBUG,
        default=logging.INFO,
    )
    parser.add_argument(
        "-a",
        "--av-scan",
        help="Run VirusTotal scan on all DLLs",
        dest="api_key",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-ad",
        "--av-scan-delay",
        help="Minimum delay (in seconds) between VirusTotal scans",
        dest="av_scan_delay",
        type=float,
        default=15.0,
    )
    args = parser.parse_args()
    logging.getLogger().setLevel(args.log_level)

    if not os.path.exists(args.modlist):
        logging.error(f"Could not find mod list at specified path: {args.modlist}")
        sys.exit(0)

    mods = get_mods(args.modlist)

    logging.info(f"Scanning {len(mods)} mods...")
    logging.debug(f"Mods to scan:")
    for mod in mods:
        logging.debug(f"  {mod}")

    mods = await populate_mod_urls(mods)
    logging.info(
        "Done checking mods. See the list of mods with invalid or missing github urls below"
    )
    for mod in mods:
        if mod.source_url is None:
            print(f"{mod}")

    if args.api_key:
        logging.info("Beginning AV scans...")
        async with vt.Client(args.api_key) as vt_client:
            for mod in mods:
                await mod.av_scan(vt_client, delay=args.av_scan_delay)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
