# Lethal Company Mods Checker

## What is this?

This is a script that takes a path to a mods.yml file in your r2modman profile, and gives back a list of all mods that contain dlls (executable code) that are lacking a github url on their Thunderstore page.

This helps with reviewing large modpacks you have installed to see which mods are closed source - and are therefore untrustworthy.

## Usage

Firstly, ensure you have python 3 installed (only tested on 3.10.11).

Then, cd into the repo, and install the requirements:

(Optionally, create and activate a virtual environment for running this)

```bash
pip install -r requirements.txt
```

Then, run `lcmodcheck` against your mods.yml file from your r2modman profile. Example:

```bash
python lcmodcheck.py "%AppData%\r2modmanPlus-local\LethalCompany\profiles\Da boys but funny\mods.yml"
```

## Scan exclusions

You may also add mods you already trust to the `scan_exclusions.txt` file in the repo to exclude checking those mods.

Simply add each mod name (including the author) on their own lines. Default `scan_exclusions.txt`:

```
# Enter the name of each mod to exclude from scanning on their own lines below
BepInEx-BepInExPack

```