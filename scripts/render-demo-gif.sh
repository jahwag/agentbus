#!/bin/sh
set -eu

input=${1:-docs/assets/agentbus-demo.mp4}
output=${2:-docs/assets/agentbus-demo.gif}

ffmpeg -y -i "$input" -filter_complex \
	'fps=12,scale=1000:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse=dither=bayer:bayer_scale=3' \
	"$output"
