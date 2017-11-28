# Submodule

- Add submodule rock to my project
  `git submodule add https://github.com/<user>/rock rock`
  
  Note that in old version of git, you need to down the contents of rock  
  `git submodule update --init --recursive`

- Clone the project with submodule
  `git clone --recursive <project url>`


  Or `git clone <project url>` then `git submodule update --init --recursive`

# Remove remote tag

  `git push --delete origin <tagname>`

  If you also need to delete the local tag, use:

  `git tag --delete <tagname>`

