# Submodule

- Undo a local commit
  `git reset HEAD~`

- Add submodule rock to my project
  `git submodule add https://github.com/<user>/rock rock`
  
  Note that in old version of git, you need to down the contents of rock  
  `git submodule update --init --recursive`

- Clone the project with submodule
  `git clone --recursive <project url>`


  Or `git clone <project url>` then `git submodule update --init --recursive`

- Remove a submodule

 1. git submodule deinit -f -- a/submodule  
 2. rm -rf .git/modules/a/submodule
 3. git rm -f a/submodule
  # Note: a/submodule (no trailing slash)
  # or, if you want to leave it in your working tree and have done step 0
 4. git rm --cached a/submodule
3bis mv a/submodule_tmp a/submodule


# Remove remote tag

  `git push --delete origin <tagname>`

  If you also need to delete the local tag, use:

  `git tag --delete <tagname>`

# Syncing fork with upstream

1. git remote add upstream https://github.com/otheruser/repo.git
2. git fetch upstream
3. git checkout master
4. git merge upstream/master
5. git push

