#!/usr/bin/env ruby
#
# Copyright (c) 2015 Katharina Männle
#
# Solution for 'riverside' from BostonKeyParty 2015
#
require 'rubygems'
require 'rmagick'

# input: 4 bytes in hex representation per line:
# first byte:   mouse clicks
# second byte:  relative x movement
# third byte:   relative y movement
# fourth byte:  mouse wheel
data = []
ARGF.each_line do |l|
    click, x, y, _ = [l.chomp].pack('H*').unpack('c*')
    data << [click > 0, x, y]
end


img = Magick::Image::read('keyboard.png')[0]

# Drawing for mouse movement
move = Magick::Draw.new
move.stroke 'lightblue'
move.opacity 0.4

# Drawing for mouse clicks
clicks = Magick::Draw.new
clicks.fill 'green'

# Reconstructing mouse movement starting at the bottom left corner of the screen
mouse = {:x => 0, :y => img.rows}
letters = Magick::ImageList.new
for click, dx, dy in data do
    
    if click
        x, y = mouse[:x], mouse[:y]
        clicks.circle x, y, x + 5, y + 5

        # crop keyboard image to area around the click
        letters << img.crop(x - 20 , y - 40, 50, 50)
    end

    x, y = mouse[:x] + dx, mouse[:y] + dy

    move.line mouse[:x], mouse[:y], x, y

    mouse[:x], mouse[:y] = x, y
end



move.draw img
clicks.draw img
img.write 'reconstruction.png'
puts 'reconstruction.png'

letters.append(false).write 'userinput.png'
puts 'userinput.png'
