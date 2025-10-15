# Vim Configuration

# Basic settings
set nocompatible
set number
set relativenumber
set tabstop=4
set shiftwidth=4
set expandtab
set autoindent
set smartindent
set showmatch
set incsearch
set hlsearch
set ignorecase
set smartcase

# UI settings
set showcmd
set wildmenu
set laststatus=2
set ruler
set cursorline

# Color scheme
syntax enable
set background=dark

# Key mappings
let mapleader = " "
nnoremap <leader>w :w<CR>
nnoremap <leader>q :q<CR>
nnoremap <leader>h :noh<CR>

# File type settings
filetype plugin indent on
