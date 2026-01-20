# Building the CETRA Documentation PDF

This project’s documentation is written in Markdown and compiled into a single
PDF using Pandoc and XeLaTeX.

## Requirements
- pandoc
- XeLaTeX (TeX Live)

On Arch Linux:
```bash
sudo pacman -S pandoc texlive-xetex
```


Then run the following commands from /docs
```bash
pandoc -s \
  --toc \
  --number-sections \
  --include-before-body pandoc/cover.tex \
  --pdf-engine=xelatex \
  -o CETRA-Documentation.pdf \
  $(cat pandoc/files.txt)
```

The generated PDF will be created as:
docs/CETRA-Documentation.pdf