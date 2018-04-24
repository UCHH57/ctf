# [Timisoara CTF 2018] Strange behavior (Forensics-100pts)

In this task we were given a file of unknown type.

So first, to identify the file type we use `file` linux command:

    $ file personal.bin 
    personal.bin: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "mkfs.fat", sectors/cluster 4, reserved sectors 4, root entries 512, sectors 62500 (volumes <=32 MB), Media descriptor 0xf8, sectors/FAT 64, sectors/track 32, heads 64, serial number 0x39d716e5, unlabeled, FAT (16 bit)

The file is a `DOS/MBR boot sector` so we can mount it:

    $ mkdir personal.dir
    $ sudo mount personal.bin personal.dir
    $ tree personal.dir
    personal.dir
    ├── 4_next_lectures
    │   └── fuuuuuuuun.mp4
    ├── cyber.jpg
    ├── panda_udg.jpg
    └── profile.jpg

We look at the files but nothing interesting here, so using sleuthkit we look for deleted files:

    $ fls -r ./personal.bin
    r/r 4:	profile.jpg
    r/r 6:	cyber.jpg
    r/r 8:	panda_udg.jpg
    d/d 11:	4_next_lectures
    + r/r 18247:	fuuuuuuuun.mp4
    + r/r * 18249:	schedule.xlsx
    v/v 997891:	$MBR
    v/v 997892:	$FAT1
    v/v 997893:	$FAT2
    d/d 997894:	$OrphanFiles

And we see that there is a deleted file called `schedule.xlsx`, so still using sleuthkit we retrieve it.
Then, using in2csv from csvkit we convert this file to csv to be able to read it in our terminal.

    $ icat personal.bin 18249 > schedule.xlsx
    $ in2csv schedule.xlsx > schedule.csv
    $ cat schedule.csv
    "No.
    overall","No. in
    season",Title,Directed by,Written by,Viewed,
    22,1,"""The Rickshank Rickdemption""",Juan Meza-León,Mike McMahan,x,
    23,2,"""Rickmancing the Stone""",Dominic Polcino,Jane Becker,x,
    24,3,"""Pickle Rick""",Anthony Chun,Jessica Gao,x,
    25,4,"""Vindicators 3: The Return of Worldender""",Bryan Newton,Sarah Carbiener & Erica Rosbe,x,
    26,5,"""The Whirly Dirly Conspiracy""",Juan Meza-León,Ryan Ridley,x,
    27,6,"""Rest and Ricklaxation""",Anthony Chun,Tom Kauffman,x,
    28,7,"""The Ricklantis Mixup""[b]",Dominic Polcino,Dan Guterman & Ryan Ridley,x,
    29,8,"""Morty's Mind Blowers""",Bryan Newton,"Mike McMahan, James Siciliano, Ryan Ridley,
    Dan Guterman, Justin Roiland & Dan Harmon",x,
    30,9,"""The ABC's of Beth""",Juan Meza-León,Mike McMahan,timctf{d0nt_f0rg3t_t0_h4v3_fun},
    31,10,"""The Rickchurian Mortydate""",Anthony Chun,Dan Harmon,x,
    
**Et voilà !**
