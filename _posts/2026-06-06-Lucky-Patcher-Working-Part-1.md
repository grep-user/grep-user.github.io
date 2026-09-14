---
title: Lucky Patcher Working - Adblock
published: false
---

Hey everyone, It has been long time since I have posted. 

### Background

Recently I have been playing offline android games which was really fun. While playing I also found some cool android apk hacking or modding tools 

-   Static modding
    -   [Lucky patcher](https://www.luckypatchers.com/)  
    -   [game guardian](https://gameguardian.net/forum/) - [cheatengine](https://www.cheatengine.org/) for android
    -   [Il2CppDumper](https://github.com/perfare/il2cppdumper) - Unity il2cpp reversing

I have tried all the above tools and each has its own pros and cons. Runtime mods works by scanning the memory region with our search criteria. Since the memory is filled with other variable which matches our search criteria. We can filter it out by repetitive search when our search candidate changes. Static mod works by modifying the bytecode in smali or dex code by analyzing the apk using tools like [jadx](https://github.com/skylot/jadx),  and patching the apk with modified code with tools like [apktool](https://github.com/iBotPeaches/Apktool). 


But lucky patcher provides other apk modding capabilities like ad removal, in app level and purchase emulation, rebuilding apk with additional permission and many more. In this post let's uncover how these mod works in detail.

### Adblock

I use AD removal patch for most of my apps, I expected the mod to check few domains and block those in request similar to how browser extension may use [domain list](https://easylist.to/) to block ads. In lucky patcher there are other techniques are handled to prevent ad blocks in java api level.

- remove links from APK
- Corrupt the ad receiver
- Offline patch
- Other patch
- Removing dependency
- make fully offline


