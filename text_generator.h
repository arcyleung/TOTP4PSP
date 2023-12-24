#ifndef _TEXT_GEN_H_
#define _TEXT_GEN_H_
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>

SDL_Renderer *m_renderer;
TTF_Font *font;
void init_generator(const char *file, int font_size, SDL_Renderer &renderer)
{
    TTF_Init();
    font = TTF_OpenFont(file, font_size);
    m_renderer = &renderer;
}
void cleanup_generator()
{
    TTF_Quit();
}

void gen_text_at_rect(int x, int y, const char *text, SDL_Texture **texture, SDL_Rect *rect)
{
    int text_width;
    int text_height;
    SDL_Surface *surface;
    SDL_Color textColor = {255, 255, 255, 255};

    surface = TTF_RenderUTF8_Blended(font, text, textColor);
    *texture = SDL_CreateTextureFromSurface(m_renderer, surface);
    text_width = surface->w;
    text_height = surface->h;

    rect->x = x;
    rect->y = y;
    rect->w = text_width;
    rect->h = text_height;
    SDL_FreeSurface(surface);
    SDL_RenderCopy(m_renderer, *texture, NULL, rect);
    SDL_DestroyTexture(*texture);
}
#endif