#!/usr/bin/env ruby

require 'socket'
require 'digest'
require 'io/console'


WALL     =  "\e[1m" + "\e[34m" + "\u{2588}" + "\e[0m"
VISITED  =  "\e[1m" + "\e[33m" + "."        + "\e[0m"
FINISHED =            "\e[32m" + "."        + "\e[0m"
CURSOR   =  "\e[1m" + "\e[31m" + "X"        + "\e[0m"

$s = TCPSocket.open("amazeing.hackable.software", 1337)

$sl = TCPSocket.open("amazeing.hackable.software", 31336)
$sd = TCPSocket.open("amazeing.hackable.software", 31339)
$sr = TCPSocket.open("amazeing.hackable.software", 31338)
$su = TCPSocket.open("amazeing.hackable.software", 31337)

$visited = Hash.new(false)


def findSpell sha1start
    prefix = "DrgnS"
    spell = ""
    for n in 0..5 do
        guesses = (" ".."~").to_a.combination(n).each.map { |a| a.join }
        for guess in guesses do
            sha1 = Digest::SHA1.hexdigest(prefix + guess)
            if sha1[0..2].upcase == sha1start
                return prefix + guess
            end
        end
    end
end

def draw my_pos
    rows, cols = $stdin.winsize
    rows = (rows * 0.9).to_i
    px, py = my_pos
    
    tmp = $cave[my_pos]
    $cave[my_pos] = CURSOR
    string = ""
    
    (py + rows/2).downto (py - rows/2) do |y|
        for x in 0...cols do
            string << $cave[[x,y]]
        end
        string << "\n"
    end
    print "\033[1;1H"       # reset cursor
    print string
    $cave[my_pos] = tmp 
end

def dump_cave
    $f = File.open("cave.out", "w")

    keys = $cave.keys
    xmax = keys.each.map { |k| k[0] }.max
    ymax = keys.each.map { |k| k[1] }.max

    s = ""
    ymax.downto 0 do |y|
        for x in 0..xmax do
            s << $cave[[x,y]]
        end
        s << "\n"
    end

    $f.write(s)
end


def launch_game pos
    print "\033[2J"     # clear terminal
    print "\e[?25l"     # hide cursor
    step pos, pos
    puts "Done :)"
end

def step pos, from
    $visited[pos] = true
    $cave[pos] = VISITED
    draw pos

    x, y = pos
    for dir, socket, ret in [
        [[ 1, 0], $sr, $sl],
        [[-1, 0], $sl, $sr],
        [[ 0, 1], $su, $sd],
        [[ 0,-1], $sd, $su]] do

        new = [x + dir[0], y + dir[1]]
        if not $visited[new] and not from == new and not (new[0] < 0 or new[1] < 0)
            socket.send $secret, 0
            answer = $s.gets
            if not answer.include? "Ok"
                $cave[new] = WALL
                $visited[new] = true
                draw pos
            else
                step(new, pos)
                ret.send $secret, 0
                answer = $s.gets
                draw from
            end
        end
    end
    $cave[pos] = FINISHED
end






while line = $s.gets do
    puts line
    if i = line.index("0x")
        sha1start = line[i+2..i+4]
        puts $s.gets
        break
    end
end
puts "Finding spell"
spell = findSpell sha1start
puts "===> #{spell}"
$s.send spell, 0

while line = $s.gets do
    puts line
    if i = line.index(" : ")
        $secret = line[i+3...i+43]
        break
    end

end


$cave = Hash.new(" ")
pos = [5, 5]

launch_game pos
dump_cave

$s.close
